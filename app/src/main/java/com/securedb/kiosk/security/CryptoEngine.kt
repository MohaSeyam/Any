package com.securedb.kiosk.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * ثوابت التشفير والمفتاح العام للإدارة (Ed25519).
 */
object SecurityConfig {
    // مفتاح Ed25519 العام للإدارة (32 بايت بصيغة Hex)
    const val ADMIN_ED25519_PUBLIC_KEY_HEX =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

    // معاملات Argon2id البطيئة (64MB RAM, 3 iterations, 2 lanes)
    const val ARGON2_MEMORY_KB = 65536
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 2
    const val SALT_LENGTH_BYTES = 16
    const val KEY_LENGTH_BYTES = 32

    // فترة السماح عند التواجد في الخلفية أو عدم التفاعل (15 دقيقة)
    const val SESSION_GRACE_PERIOD_MS = 15L * 60L * 1000L

    // اسم ملف قاعدة البيانات المشفرة في التخزين الداخلي المعزول
    const val DATABASE_FILENAME = "secure_catalog.db"

    // حجم الشريحة الواحدة لبث الصور والمرفقات الضخمة دون تجاوز حد CursorWindow (512 KB)
    const val BLOB_STREAM_CHUNK_BYTES = 512 * 1024
}

object CryptoEngine {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val MASTER_VAULT_AES_ALIAS = "kiosk_master_vault_aes_v2"
    const val ACTIVE_COUNTER_AES_ALIAS = "kiosk_active_counter_aes_v2"
    const val LOCKED_TOMBSTONE_AES_ALIAS = "kiosk_locked_tombstone_aes_v2"
    private const val DEVICE_RSA_WRAP_ALIAS = "kiosk_device_rsa_oaep_v2"

    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_BITS = 128

    private val secureRandom = SecureRandom()

    fun randomBytes(length: Int): ByteArray {
        val out = ByteArray(length)
        secureRandom.nextBytes(out)
        return out
    }

    /**
     * اشتقاق مفتاح بطيء وعشوائي عبر خوارزمية Argon2id القياسية (RFC 9106 v1.3).
     * متزامن (@Synchronized) لمنع تشغيل عمليتي 64MB بالتوازي واستنزاف الـ Heap.
     */
    @Synchronized
    fun deriveArgon2id(
        password: CharArray,
        salt: ByteArray,
        memoryKb: Int = SecurityConfig.ARGON2_MEMORY_KB,
        iterations: Int = SecurityConfig.ARGON2_ITERATIONS,
        parallelism: Int = SecurityConfig.ARGON2_PARALLELISM,
        outputBytes: Int = SecurityConfig.KEY_LENGTH_BYTES
    ): ByteArray {
        val passwordBytes = charsToUtf8Bytes(password)
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memoryKb)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .build()

            val generator = Argon2BytesGenerator()
            generator.init(params)
            val result = ByteArray(outputBytes)
            generator.generateBytes(passwordBytes, result, 0, outputBytes)
            return result
        } finally {
            zeroize(passwordBytes)
        }
    }

    /**
     * التحقق من التوقيع الرقمي Ed25519 الصادر من جهاز إصدار التراخيص لدى الإدارة.
     */
    fun verifyEd25519(
        messageBytes: ByteArray,
        signatureBytes: ByteArray,
        publicKeyHex: String = SecurityConfig.ADMIN_ED25519_PUBLIC_KEY_HEX
    ): Boolean {
        if (signatureBytes.size != 64) return false
        return try {
            val pubKeyBytes = hexToBytes(publicKeyHex)
            val pubKeyParams = Ed25519PublicKeyParameters(pubKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pubKeyParams)
            verifier.update(messageBytes, 0, messageBytes.size)
            verifier.verifySignature(signatureBytes)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * تشفير وتوثيق البيانات عبر شريحة Android Keystore بخوارزمية AES-256-GCM تحت مفتاح محدد.
     */
    fun encryptWithKeystore(
        context: Context,
        plaintext: ByteArray,
        aad: ByteArray,
        keyAlias: String = MASTER_VAULT_AES_ALIAS
    ): ByteArray {
        val secretKey = getOrCreateKeystoreAesKey(context, keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        cipher.updateAAD(aad)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        val combined = ByteArray(1 + iv.size + ciphertext.size)
        combined[0] = iv.size.toByte()
        System.arraycopy(iv, 0, combined, 1, iv.size)
        System.arraycopy(ciphertext, 0, combined, 1 + iv.size, ciphertext.size)
        return combined
    }

    /**
     * فك التشفير والتحقق من عدم التلاعب عبر Android Keystore.
     * يفشل فوراً إذا تم حذف المفتاح العتادي (Anti-Rollback) أو تعديل أي بايت في الملف.
     */
    fun decryptWithKeystore(
        context: Context,
        blob: ByteArray,
        aad: ByteArray,
        keyAlias: String = MASTER_VAULT_AES_ALIAS
    ): ByteArray {
        require(blob.size > 1 + GCM_IV_LENGTH + 16) { "Invalid encrypted state blob" }
        val ivLen = blob[0].toInt() and 0xFF
        require(ivLen in 12..16 && blob.size > 1 + ivLen + 16) { "Corrupted IV length" }

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
            ?: throw SecurityException("Keystore alias missing or destroyed: $keyAlias")

        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ciphertext = blob.copyOfRange(1 + ivLen, blob.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, entry.secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    /**
     * تدمير مفتاح عتادي داخل شريحة Android Keystore لمنع هجمات استعادة نسخة قديمة من ملف العداد (Anti-Rollback).
     */
    fun destroyKeystoreKey(keyAlias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
        } catch (_: Exception) {
        }
    }

    /**
     * توليد/استرجاع زوج مفاتيح RSA-2048 OAEP داخل عتاد Android Keystore لتغليف مفتاح قاعدة البيانات (DEK)
     * بحيث لا يظهر مفتاح القاعدة مكشوفاً أبداً داخل رموز الترخيص!
     */
    fun getDeviceRsaPublicKeyDerBase64Url(context: Context): String {
        ensureDeviceRsaKeyPair(context)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val pubBytes = keyStore.getCertificate(DEVICE_RSA_WRAP_ALIAS).publicKey.encoded
        return Base64.encodeToString(
            pubBytes,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
    }

    fun getHardwareKeyFingerprintHex(context: Context): String {
        ensureDeviceRsaKeyPair(context)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val pubBytes = keyStore.getCertificate(DEVICE_RSA_WRAP_ALIAS).publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256").digest(pubBytes)
        return bytesToHex(digest).take(24)
    }

    /**
     * فك تشفير مفتاح القاعدة (DEK) المغلف بالمفتاح العام لهذا الجهاز داخل شريحة Android Keystore مباشرة.
     * متوافق 100% مع جميع شرائح TEE/StrongBox عبر OAEP(SHA-256, MGF1-SHA1).
     */
    fun unwrapDekWithDeviceRsa(context: Context, encryptedDekBytes: ByteArray): ByteArray {
        ensureDeviceRsaKeyPair(context)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKeyEntry = keyStore.getEntry(DEVICE_RSA_WRAP_ALIAS, null) as KeyStore.PrivateKeyEntry

        val oaepSpec = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey, oaepSpec)
        return cipher.doFinal(encryptedDekBytes)
    }

    /**
     * تشفير بمفتاح الجهاز العام محلياً (للتجريب المختبري قبل القفل).
     */
    fun wrapDekWithDeviceRsaPublic(context: Context, rawDekBytes: ByteArray): ByteArray {
        ensureDeviceRsaKeyPair(context)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val publicKey = keyStore.getCertificate(DEVICE_RSA_WRAP_ALIAS).publicKey

        val oaepSpec = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec)
        return cipher.doFinal(rawDekBytes)
    }

    /**
     * تشفير وتوثيق متماثل AES-256-GCM بمفتاح مشتق عبر Argon2id.
     */
    fun encryptWithRawKey(key32: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val iv = randomBytes(GCM_IV_LENGTH)
        val spec = SecretKeySpec(key32, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, spec, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)

        val out = ByteArray(GCM_IV_LENGTH + ciphertext.size)
        System.arraycopy(iv, 0, out, 0, GCM_IV_LENGTH)
        System.arraycopy(ciphertext, 0, out, GCM_IV_LENGTH, ciphertext.size)
        return out
    }

    fun decryptWithRawKey(key32: ByteArray, blob: ByteArray, aad: ByteArray): ByteArray {
        require(blob.size > GCM_IV_LENGTH + 16) { "Invalid wrapped key blob" }
        val iv = blob.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = blob.copyOfRange(GCM_IV_LENGTH, blob.size)
        val spec = SecretKeySpec(key32, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, spec, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun ensureDeviceRsaKeyPair(context: Context) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(DEVICE_RSA_WRAP_ALIAS)) return

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            DEVICE_RSA_WRAP_ALIAS,
            KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

        // RSA-2048 في TEE مدعوم عالمياً على كافة المعالجات وبسرعة عالية
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    private fun getOrCreateKeystoreAesKey(context: Context, alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        ) {
            builder.setIsStrongBoxBacked(true)
        }

        return try {
            kg.init(builder.build())
            kg.generateKey()
        } catch (_: Exception) {
            val teeSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
            kg.init(teeSpec)
            kg.generateKey()
        }
    }

    fun sha256Hex(bytes: ByteArray): String =
        bytesToHex(MessageDigest.getInstance("SHA-256").digest(bytes))

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun zeroize(vararg buffers: ByteArray?) {
        for (buf in buffers) {
            if (buf != null) Arrays.fill(buf, 0.toByte())
        }
    }

    fun zeroizeChars(vararg buffers: CharArray?) {
        for (buf in buffers) {
            if (buf != null) Arrays.fill(buf, '\u0000')
        }
    }

    private fun charsToUtf8Bytes(chars: CharArray): ByteArray {
        val byteBuffer: ByteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars))
        val bytes = ByteArray(byteBuffer.remaining())
        byteBuffer.get(bytes)
        if (byteBuffer.hasArray()) {
            Arrays.fill(byteBuffer.array(), 0.toByte())
        }
        return bytes
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "Odd hex string" }
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
