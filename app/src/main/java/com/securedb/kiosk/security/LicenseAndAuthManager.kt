package com.securedb.kiosk.security

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlin.math.max

class LicenseAndAuthManager(
    private val context: Context,
    private val guard: LockoutAndTimeGuard
) {
    companion object {
        private const val REQUEST_STATE_FILE = "activation_request.sec"
        private const val LICENSE_STATE_FILE = "license_vault.sec"
        private const val UNLOCK_CHALLENGE_FILE = "unlock_challenge.sec"

        private val REQ_AAD = "ACTIVATION_REQ_V2".toByteArray(StandardCharsets.UTF_8)
        private val VAULT_AAD = "LICENSE_VAULT_V2".toByteArray(StandardCharsets.UTF_8)
        private val USER_DEK_AAD = "USER_WRAPPED_DEK_V2".toByteArray(StandardCharsets.UTF_8)
        private val UNLOCK_AAD = "PHYSICAL_UNLOCK_V2".toByteArray(StandardCharsets.UTF_8)
    }

    data class ActivationRequestInfo(
        val deviceId: String,
        val nonceHex: String,
        val dbProvisioned: Boolean,
        val requestCode: String
    )

    data class VerifiedLicensePendingUser(
        val licenseId: String,
        val deviceId: String,
        val issuedAtMs: Long,
        val expiresAtMs: Long,
        val wrappedDekBytes: ByteArray
    )

    private val requestFile: File
        get() = File(context.noBackupFilesDir, REQUEST_STATE_FILE)

    private val vaultFile: File
        get() = File(context.noBackupFilesDir, LICENSE_STATE_FILE)

    private val unlockChallengeFile: File
        get() = File(context.noBackupFilesDir, UNLOCK_CHALLENGE_FILE)

    fun isActivated(): Boolean = vaultFile.exists()

    @SuppressLint("HardwareIds")
    fun getDeviceId(): String {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "unknown"
        val keystoreFp = CryptoEngine.getHardwareKeyFingerprintHex(context)
        val raw = "$androidId|${Build.MANUFACTURER}|${Build.MODEL}|${Build.BOARD}|$keystoreFp"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(StandardCharsets.UTF_8))
        return "DEV-" + CryptoEngine.bytesToHex(digest).take(16).uppercase()
    }

    @Synchronized
    fun getOrCreateActivationRequest(labRawDekBytes: ByteArray? = null): ActivationRequestInfo {
        val deviceId = getDeviceId()
        val rsaPubB64 = CryptoEngine.getDeviceRsaPublicKeyDerBase64Url(context)
        val dbFile = context.getDatabasePath(SecurityConfig.DATABASE_FILENAME)

        var nonceHex = ""
        var preWrappedLabDekB64 = ""

        if (labRawDekBytes != null) {
            try {
                val wrapped = CryptoEngine.wrapDekWithDeviceRsaPublic(context, labRawDekBytes)
                preWrappedLabDekB64 = Base64.encodeToString(
                    wrapped,
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                )
            } finally {
                CryptoEngine.zeroize(labRawDekBytes)
            }
            nonceHex = CryptoEngine.bytesToHex(CryptoEngine.randomBytes(12))
            persistRequestState(deviceId, nonceHex, preWrappedLabDekB64)
        } else if (requestFile.exists()) {
            try {
                val dec = CryptoEngine.decryptWithKeystore(context, requestFile.readBytes(), REQ_AAD)
                val saved = JSONObject(String(dec, StandardCharsets.UTF_8))
                nonceHex = saved.getString("nonceHex")
                preWrappedLabDekB64 = saved.optString("wrappedLabDekB64", "")
            } catch (_: Exception) {
                requestFile.delete()
            }
        }

        if (nonceHex.isEmpty()) {
            nonceHex = CryptoEngine.bytesToHex(CryptoEngine.randomBytes(12))
            persistRequestState(deviceId, nonceHex, preWrappedLabDekB64)
        }

        val publicRequestJson = JSONObject().apply {
            put("v", 2)
            put("type", "ACTIVATE_REQ")
            put("deviceId", deviceId)
            put("nonce", nonceHex)
            put("rsaPub", rsaPubB64)
            if (preWrappedLabDekB64.isNotEmpty()) {
                put("encLabDek", preWrappedLabDekB64)
            }
        }.toString()

        val code = "REQ2." + Base64.encodeToString(
            publicRequestJson.toByteArray(StandardCharsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )

        return ActivationRequestInfo(
            deviceId = deviceId,
            nonceHex = nonceHex,
            dbProvisioned = dbFile.exists() && dbFile.length() > 0,
            requestCode = code
        )
    }

    @Synchronized
    fun verifyLicenseAndAdminPassword(
        licenseToken: String,
        adminPassword: CharArray
    ): VerifiedLicensePendingUser {
        val clean = licenseToken.replace(Regex("\\s+"), "")
        require(clean.startsWith("LIC2.")) { "صيغة مفتاح الترخيص غير صالحة (يجب أن يبدأ بـ LIC2.)" }

        val parts = clean.removePrefix("LIC2.").split(".")
        require(parts.size == 2) { "بنية مفتاح الترخيص غير مكتملة" }

        val payloadBytes = Base64.decode(parts[0], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val sigBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        if (!CryptoEngine.verifyEd25519(payloadBytes, sigBytes)) {
            throw SecurityException("فشل التحقق من التوقيع الرقمي (Ed25519) لمفتاح الترخيص!")
        }

        val payload = JSONObject(String(payloadBytes, StandardCharsets.UTF_8))
        require(payload.optString("type") == "LICENSE") { "نوع الشهادة غير صالح" }

        val expectedReq = getOrCreateActivationRequest()
        if (payload.optString("deviceId") != expectedReq.deviceId) {
            throw SecurityException("مفتاح الترخيص هذا مخصص لجهاز آخر ولا يعمل على هذا الجهاز!")
        }
        if (payload.optString("nonce") != expectedReq.nonceHex) {
            throw SecurityException("رمز التحدي (Nonce) في الترخيص غير مطابق لطلب التفعيل الحالي!")
        }

        val issuedAtMs = payload.getLong("issuedAtMs")
        val expiresAtMs = payload.getLong("expiresAtMs")
        val refNow = max(System.currentTimeMillis(), issuedAtMs)
        require(expiresAtMs > refNow) { "تاريخ صلاحية هذا الترخيص منتهٍ بالفعل!" }

        val adminSalt = CryptoEngine.hexToBytes(payload.getString("adminSaltHex"))
        val expectedAdminHash = CryptoEngine.hexToBytes(payload.getString("adminVerifierHex"))
        val adminMemKb = payload.optInt("argonMemKb", SecurityConfig.ARGON2_MEMORY_KB)
        val adminIter = payload.optInt("argonIter", SecurityConfig.ARGON2_ITERATIONS)

        val computedAdminHash = CryptoEngine.deriveArgon2id(
            password = adminPassword,
            salt = adminSalt,
            memoryKb = adminMemKb,
            iterations = adminIter
        )
        try {
            if (!CryptoEngine.constantTimeEquals(computedAdminHash, expectedAdminHash)) {
                throw SecurityException("كلمة مرور المدير (Admin) غير صحيحة!")
            }
        } finally {
            CryptoEngine.zeroize(computedAdminHash)
        }

        val wrappedDekB64 = payload.getString("wrappedDekB64")
        val wrappedDekBytes = Base64.decode(
            wrappedDekB64,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )

        return VerifiedLicensePendingUser(
            licenseId = payload.getString("licenseId"),
            deviceId = expectedReq.deviceId,
            issuedAtMs = issuedAtMs,
            expiresAtMs = expiresAtMs,
            wrappedDekBytes = wrappedDekBytes
        )
    }

    @Synchronized
    fun completeActivationWithUserCredentials(
        verifiedLicense: VerifiedLicensePendingUser,
        username: String,
        userPassword: CharArray
    ) {
        val cleanUser = username.trim()
        require(cleanUser.length >= 3) { "يجب ألا يقل اسم المستخدم عن 3 أحرف" }
        require(userPassword.size >= 6) { "يجب ألا تقل كلمة مرور المستخدم عن 6 خانات" }

        val rawDekBytes = CryptoEngine.unwrapDekWithDeviceRsa(context, verifiedLicense.wrappedDekBytes)
        try {
            require(rawDekBytes.size == 32) { "طول مفتاح قاعدة البيانات المسترد غير صالح" }

            val userHashSalt = CryptoEngine.randomBytes(SecurityConfig.SALT_LENGTH_BYTES)
            val authSalt = CryptoEngine.randomBytes(SecurityConfig.SALT_LENGTH_BYTES)
            val wrapSalt = CryptoEngine.randomBytes(SecurityConfig.SALT_LENGTH_BYTES)

            val userChars = cleanUser.toCharArray()
            val usernameHash = CryptoEngine.deriveArgon2id(userChars, userHashSalt)
            val passwordVerifier = CryptoEngine.deriveArgon2id(userPassword, authSalt)
            val userWrappingKey = CryptoEngine.deriveArgon2id(userPassword, wrapSalt)

            try {
                val userWrappedDek = CryptoEngine.encryptWithRawKey(userWrappingKey, rawDekBytes, USER_DEK_AAD)

                val vaultJson = JSONObject().apply {
                    put("licenseId", verifiedLicense.licenseId)
                    put("deviceId", verifiedLicense.deviceId)
                    put("issuedAtMs", verifiedLicense.issuedAtMs)
                    put("expiresAtMs", verifiedLicense.expiresAtMs)
                    put("userSaltHex", CryptoEngine.bytesToHex(userHashSalt))
                    put("usernameVerifierHex", CryptoEngine.bytesToHex(usernameHash))
                    put("authSaltHex", CryptoEngine.bytesToHex(authSalt))
                    put("passwordVerifierHex", CryptoEngine.bytesToHex(passwordVerifier))
                    put("wrapSaltHex", CryptoEngine.bytesToHex(wrapSalt))
                    put("userWrappedDekHex", CryptoEngine.bytesToHex(userWrappedDek))
                }.toString().toByteArray(StandardCharsets.UTF_8)

                val encryptedVault = CryptoEngine.encryptWithKeystore(context, vaultJson, VAULT_AAD)
                writeAtomically(vaultFile, encryptedVault)

                guard.initializeOnActivation(verifiedLicense.issuedAtMs)
                requestFile.delete()
            } finally {
                CryptoEngine.zeroizeChars(userChars)
                CryptoEngine.zeroize(usernameHash, passwordVerifier, userWrappingKey)
            }
        } finally {
            CryptoEngine.zeroize(rawDekBytes)
        }
    }

    @Synchronized
    fun getLicenseExpiryMs(): Long {
        val vault = readDecryptedVault()
        return vault.getLong("expiresAtMs")
    }

    @Synchronized
    fun authenticateUserAndUnwrapDbKey(
        username: String,
        password: CharArray
    ): Result<ByteArray> {
        val lockSnap = guard.inspectAndRefreshLockout()
        if (lockSnap.permanentlyLocked) {
            return Result.failure(PermanentLockException(lockSnap.permanentReason))
        }
        if (lockSnap.remainingLockMs > 0L) {
            return Result.failure(TemporaryLockException(lockSnap.remainingLockMs, lockSnap.failedAttempts))
        }

        val vault = try {
            readDecryptedVault()
        } catch (_: Exception) {
            val snap = guard.triggerPermanentLock("فشل التحقق من سلامة خزنة الترخيص الداخلية (تلاعب أمني)")
            return Result.failure(PermanentLockException(snap.permanentReason))
        }

        val timeError = guard.verifyMonotonicTimeAndExpiry(vault.getLong("expiresAtMs"))
        if (timeError != null) {
            return Result.failure(PermanentLockException(timeError))
        }

        val userSalt = CryptoEngine.hexToBytes(vault.getString("userSaltHex"))
        val expectedUserHash = CryptoEngine.hexToBytes(vault.getString("usernameVerifierHex"))
        val authSalt = CryptoEngine.hexToBytes(vault.getString("authSaltHex"))
        val expectedPassHash = CryptoEngine.hexToBytes(vault.getString("passwordVerifierHex"))

        val userChars = username.trim().toCharArray()
        val computedUserHash = CryptoEngine.deriveArgon2id(userChars, userSalt)
        val computedPassHash = CryptoEngine.deriveArgon2id(password, authSalt)
        CryptoEngine.zeroizeChars(userChars)

        val userOk = CryptoEngine.constantTimeEquals(computedUserHash, expectedUserHash)
        val passOk = CryptoEngine.constantTimeEquals(computedPassHash, expectedPassHash)
        CryptoEngine.zeroize(computedUserHash, computedPassHash)

        if (!userOk || !passOk) {
            val updated = guard.recordFailedLoginAttempt()
            return if (updated.permanentlyLocked) {
                Result.failure(PermanentLockException(updated.permanentReason))
            } else if (updated.remainingLockMs > 0L) {
                Result.failure(TemporaryLockException(updated.remainingLockMs, updated.failedAttempts))
            } else {
                Result.failure(InvalidCredentialsException(updated.failedAttempts))
            }
        }

        val wrapSalt = CryptoEngine.hexToBytes(vault.getString("wrapSaltHex"))
        val userWrappedDek = CryptoEngine.hexToBytes(vault.getString("userWrappedDekHex"))
        val userWrapKey = CryptoEngine.deriveArgon2id(password, wrapSalt)
        return try {
            val rawDek = CryptoEngine.decryptWithRawKey(userWrapKey, userWrappedDek, USER_DEK_AAD)
            guard.resetOnSuccessfulLogin()
            Result.success(rawDek)
        } catch (_: Exception) {
            Result.failure(SecurityException("تعذر فك تغليف مفتاح قاعدة البيانات"))
        } finally {
            CryptoEngine.zeroize(userWrapKey)
        }
    }

    @Synchronized
    fun generatePhysicalUnlockChallenge(): String {
        val deviceId = getDeviceId()
        val nonceHex = CryptoEngine.bytesToHex(CryptoEngine.randomBytes(12))
        val state = JSONObject().apply {
            put("deviceId", deviceId)
            put("nonceHex", nonceHex)
        }.toString().toByteArray(StandardCharsets.UTF_8)
        writeAtomically(unlockChallengeFile, CryptoEngine.encryptWithKeystore(context, state, UNLOCK_AAD))

        val publicJson = JSONObject().apply {
            put("v", 2)
            put("type", "UNLOCK_REQ")
            put("deviceId", deviceId)
            put("nonce", nonceHex)
        }.toString()

        return "UNLKREQ2." + Base64.encodeToString(
            publicJson.toByteArray(StandardCharsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
    }

    @Synchronized
    fun verifyPhysicalAdminUnlock(unlockToken: String, adminPassword: CharArray) {
        require(unlockChallengeFile.exists()) { "لا يوجد طلب فتح نشط على هذا الجهاز" }
        val clean = unlockToken.replace(Regex("\\s+"), "")
        require(clean.startsWith("UNLK2.")) { "صيغة أمر الفتح الإداري غير صالحة" }

        val parts = clean.removePrefix("UNLK2.").split(".")
        require(parts.size == 2) { "بنية أمر الفتح غير مكتملة" }

        val payloadBytes = Base64.decode(parts[0], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val sigBytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        if (!CryptoEngine.verifyEd25519(payloadBytes, sigBytes)) {
            unlockChallengeFile.delete()
            throw SecurityException("فشل التحقق من توقيع المدير الرقمي (Ed25519)!")
        }

        val savedState = JSONObject(
            String(CryptoEngine.decryptWithKeystore(context, unlockChallengeFile.readBytes(), UNLOCK_AAD), StandardCharsets.UTF_8)
        )
        // استهلاك وحرق رمز التحدي لمرة واحدة فوراً لمنع إعادة المحاولة البرمجية على نفس التوكن
        unlockChallengeFile.delete()

        val payload = JSONObject(String(payloadBytes, StandardCharsets.UTF_8))
        require(payload.optString("type") == "UNLOCK") { "نوع الأمر غير صالح" }
        require(payload.optString("deviceId") == savedState.getString("deviceId")) { "الأمر غير مخصص لهذا الجهاز" }
        require(payload.optString("nonce") == savedState.getString("nonceHex")) { "رمز التحدي منتهي أو غير مطابق" }

        val adminSalt = CryptoEngine.hexToBytes(payload.getString("adminSaltHex"))
        val expectedAdminHash = CryptoEngine.hexToBytes(payload.getString("adminVerifierHex"))
        val adminMemKb = payload.optInt("argonMemKb", SecurityConfig.ARGON2_MEMORY_KB)
        val adminIter = payload.optInt("argonIter", SecurityConfig.ARGON2_ITERATIONS)

        val computed = CryptoEngine.deriveArgon2id(
            password = adminPassword,
            salt = adminSalt,
            memoryKb = adminMemKb,
            iterations = adminIter
        )
        try {
            if (!CryptoEngine.constantTimeEquals(computed, expectedAdminHash)) {
                throw SecurityException("كلمة مرور تفويض المدير غير صحيحة!")
            }
        } finally {
            CryptoEngine.zeroize(computed)
        }

        val adminNowMs = payload.getLong("adminCurrentTimeMs")
        val refNowMs = max(System.currentTimeMillis(), adminNowMs)
        val newExpiresAtMs = payload.optLong("newExpiresAtMs", 0L)

        if (vaultFile.exists()) {
            val vault = readDecryptedVault()
            val currentExpires = vault.getLong("expiresAtMs")
            val effectiveExpires = if (newExpiresAtMs > 0L) max(currentExpires, newExpiresAtMs) else currentExpires
            require(effectiveExpires > refNowMs) {
                "صلاحية ترخيص هذا الجهاز منتهية — مرر خيار تمديد الأيام (--extend-days) في أداة المدير أثناء الفتح!"
            }
            if (effectiveExpires != currentExpires) {
                vault.put("expiresAtMs", effectiveExpires)
                val reEncrypted = CryptoEngine.encryptWithKeystore(
                    context,
                    vault.toString().toByteArray(StandardCharsets.UTF_8),
                    VAULT_AAD
                )
                writeAtomically(vaultFile, reEncrypted)
            }
        }

        guard.performPhysicalAdminReset(adminNowMs)
    }

    private fun persistRequestState(deviceId: String, nonceHex: String, wrappedLabDekB64: String) {
        val state = JSONObject().apply {
            put("deviceId", deviceId)
            put("nonceHex", nonceHex)
            put("wrappedLabDekB64", wrappedLabDekB64)
        }.toString().toByteArray(StandardCharsets.UTF_8)
        writeAtomically(requestFile, CryptoEngine.encryptWithKeystore(context, state, REQ_AAD))
    }

    private fun readDecryptedVault(): JSONObject {
        require(vaultFile.exists()) { "الجهاز غير مفعل" }
        val decrypted = CryptoEngine.decryptWithKeystore(context, vaultFile.readBytes(), VAULT_AAD)
        return JSONObject(String(decrypted, StandardCharsets.UTF_8))
    }

    private fun writeAtomically(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(target)) {
            target.writeBytes(bytes)
            tmp.delete()
        }
    }
}

class TemporaryLockException(val remainingMs: Long, val attempts: Int) :
    Exception("تم قفل الدخول مؤقتاً بسبب تكرار المحاولات الخاطئة")

class PermanentLockException(val reason: String) :
    Exception(reason)

class InvalidCredentialsException(val attempts: Int) :
    Exception("اسم المستخدم أو كلمة المرور غير صحيحة (محاولة رقم $attempts)")
