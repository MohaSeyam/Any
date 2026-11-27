package com.securedb.kiosk

import com.securedb.kiosk.db.SecureReadOnlyDbEngine
import com.securedb.kiosk.security.CryptoEngine
import com.securedb.kiosk.security.LockoutAndTimeGuard
import com.securedb.kiosk.security.SecurityConfig
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import javax.crypto.AEADBadTagException

/**
 * اختبارات الوحدات الآلية (JVM Unit Tests) للتحقق من:
 * 1. صحة اشتقاق المفاتيح البطيء Argon2id وحساسيته لتغير كلمة المرور والـ Salt.
 * 2. صحة التحقق من التوقيع الرقمي Ed25519 ورفض أي تلاعب ببت واحد.
 * 3. التشفير المتماثل AES-256-GCM وكشف التلاعب بالبيانات أو بالـ AAD.
 * 4. تطابق سلم عقوبات محاولات الدخول الفاشلة (1..10) حرفياً مع المتطلبات.
 * 5. سلامة محول استعلامات FTS5 ضد الرموز الخاصة والعربية.
 * 6. تصفير المفاتيح من الذاكرة العشوائية (RAM Zeroization).
 */
class SecurityCoreUnitTest {

    @Test
    fun argon2id_derivesDeterministicKeyAndRejectsWrongPassword() {
        val salt1 = CryptoEngine.hexToBytes("000102030405060708090a0b0c0d0e0f")
        val salt2 = CryptoEngine.hexToBytes("ff0102030405060708090a0b0c0d0e0f")

        // استخدام ذاكرة مصغرة داخل اختبار الوحدة السريع مع التحقق من نفس محرك Argon2id
        val k1 = CryptoEngine.deriveArgon2id("StrongPass#2026".toCharArray(), salt1, memoryKb = 4096, iterations = 2)
        val k2 = CryptoEngine.deriveArgon2id("StrongPass#2026".toCharArray(), salt1, memoryKb = 4096, iterations = 2)
        val kWrongPass = CryptoEngine.deriveArgon2id("StrongPass#2027".toCharArray(), salt1, memoryKb = 4096, iterations = 2)
        val kDiffSalt = CryptoEngine.deriveArgon2id("StrongPass#2026".toCharArray(), salt2, memoryKb = 4096, iterations = 2)

        assertEquals(32, k1.size)
        assertArrayEquals(k1, k2)
        assertFalse(CryptoEngine.constantTimeEquals(k1, kWrongPass))
        assertFalse(CryptoEngine.constantTimeEquals(k1, kDiffSalt))
    }

    @Test
    fun ed25519_verifiesAuthenticSignatureAndRejectsBitFlip() {
        // RFC 8032 Test Vector 1 seed matching SecurityConfig.ADMIN_ED25519_PUBLIC_KEY_HEX
        val seed = CryptoEngine.hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val privParams = Ed25519PrivateKeyParameters(seed, 0)
        val payload = """{"type":"LICENSE","deviceId":"DEV-123456"}""".toByteArray(StandardCharsets.UTF_8)

        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(payload, 0, payload.size)
        val sig = signer.generateSignature()

        assertTrue(CryptoEngine.verifyEd25519(payload, sig, SecurityConfig.ADMIN_ED25519_PUBLIC_KEY_HEX))

        // قلب بت واحد في الرسالة يجب أن يفشل التحقق فوراً
        val tamperedPayload = payload.copyOf().also { it[5] = (it[5].toInt() xor 0x01).toByte() }
        assertFalse(CryptoEngine.verifyEd25519(tamperedPayload, sig, SecurityConfig.ADMIN_ED25519_PUBLIC_KEY_HEX))

        // قلب بت واحد في التوقيع يجب أن يفشل التحقق فوراً
        val tamperedSig = sig.copyOf().also { it[10] = (it[10].toInt() xor 0x01).toByte() }
        assertFalse(CryptoEngine.verifyEd25519(payload, tamperedSig, SecurityConfig.ADMIN_ED25519_PUBLIC_KEY_HEX))
    }

    @Test(expected = AEADBadTagException::class)
    fun aesGcmRawWrapping_detectsTampering() {
        val key = CryptoEngine.randomBytes(32)
        val secretDek = CryptoEngine.randomBytes(32)
        val aad = "USER_WRAPPED_DEK_V2".toByteArray(StandardCharsets.UTF_8)

        val wrapped = CryptoEngine.encryptWithRawKey(key, secretDek, aad)
        val recovered = CryptoEngine.decryptWithRawKey(key, wrapped, aad)
        assertArrayEquals(secretDek, recovered)

        // التلاعب ببايت واحد في النص المشفر يجب أن يرمي AEADBadTagException
        wrapped[wrapped.size - 3] = (wrapped[wrapped.size - 3].toInt() xor 0xFF).toByte()
        CryptoEngine.decryptWithRawKey(key, wrapped, aad)
    }

    @Test
    fun progressiveLockoutSchedule_matchesRequirementsDocumentExactly() {
        assertEquals(0L, LockoutAndTimeGuard.computePenaltyMsForAttempt(1))
        assertEquals(0L, LockoutAndTimeGuard.computePenaltyMsForAttempt(2))
        assertEquals(30_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(3))            // 30 ثانية
        assertEquals(0L, LockoutAndTimeGuard.computePenaltyMsForAttempt(4))                 // المحاولة الرابعة قبل إتمام المحاولتين الإضافيتين
        assertEquals(60_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(5))            // دقيقة
        assertEquals(5L * 60_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(6))       // 5 دقائق
        assertEquals(10L * 60_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(7))      // 10 دقائق
        assertEquals(60L * 60_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(8))      // ساعة
        assertEquals(6L * 60L * 60_000L, LockoutAndTimeGuard.computePenaltyMsForAttempt(9)) // 6 ساعات
        assertEquals(-1L, LockoutAndTimeGuard.computePenaltyMsForAttempt(10))               // إغلاق نهائي للمدير
        assertEquals(-1L, LockoutAndTimeGuard.computePenaltyMsForAttempt(11))
    }

    @Test
    fun fts5QuerySanitizer_handlesArabicAndStripsUnsafeOperators() {
        val q1 = SecureReadOnlyDbEngine.buildSafeFts5Query("مخطط هندسي 001")
        assertEquals("\"مخطط\"* AND \"هندسي\"* AND \"001\"*", q1)

        val q2 = SecureReadOnlyDbEngine.buildSafeFts5Query("  \"*'():^+-|  ")
        assertNull(q2)

        val q3 = SecureReadOnlyDbEngine.buildSafeFts5Query("SEC-REF-00001")
        assertNotNull(q3)
        assertEquals("\"SEC\"* AND \"REF\"* AND \"00001\"*", q3)
    }

    @Test
    fun zeroize_wipesSensitiveArraysCompletely() {
        val bytes = byteArrayOf(1, 2, 3, 4, 5)
        val chars = charArrayOf('S', 'e', 'c', 'r', 'e', 't')
        CryptoEngine.zeroize(bytes)
        CryptoEngine.zeroizeChars(chars)

        assertTrue(bytes.all { it == 0.toByte() })
        assertTrue(chars.all { it == '\u0000' })
    }
}
