package com.securedb.kiosk.security

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import com.securedb.kiosk.kiosk.KioskPolicyManager
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import kotlin.math.abs
import kotlin.math.max

/**
 * مدير عداد محاولات الفشل التصاعدي وحارس الوقت التصاعدي (الإصدار المحصن والمراجع V2.1):
 * - يعتمد عداد الإقلاع الحقيقي للنظام (Settings.Global.BOOT_COUNT) للتمييز الدقيق بين نفس جلسة التشغيل
 *   وبين إيقاف تشغيل الهاتف وإعادة فتحه بشكل طبيعي (يمنع أي إغلاق خاطئ بعد إطفاء الجهاز).
 * - يحفظ فارق التوقيت المعتمد من حاسوب الإدارة (clockOffsetMs) لتفادي أي تعارض إذا كانت ساعة حاسوب الإدارة
 *   متقدمة ببضع ثوانٍ أو دقائق عن ساعة الجوال المعزول عن الإنترنت.
 * - يدمر مفتاح العداد النشط داخل شريحة Android Keystore عند الإغلاق النهائي لمنع استرجاع نسخة قديمة (Anti-Rollback).
 */
class LockoutAndTimeGuard(private val context: Context) {

    companion object {
        private const val COUNTER_FILE_NAME = "failure_counter.sec"
        private const val TOMBSTONE_FILE_NAME = "permanent_lock.sec"
        private const val TIME_FILE_NAME = "monotonic_time.sec"

        private val COUNTER_AAD = "LOCKOUT_SENTINEL_V2".toByteArray(StandardCharsets.UTF_8)
        private val TOMBSTONE_AAD = "LOCKOUT_TOMBSTONE_V2".toByteArray(StandardCharsets.UTF_8)
        private val TIME_AAD = "MONOTONIC_TIME_GUARD_V2".toByteArray(StandardCharsets.UTF_8)

        private const val CLOCK_ROLLBACK_TOLERANCE_MS = 5_000L
        private const val IN_BOOT_DRIFT_TOLERANCE_MS = 60_000L

        fun computePenaltyMsForAttempt(attemptNumber: Int): Long = when {
            attemptNumber >= 10 -> -1L                  // إغلاق نهائي يتطلب نقل الجهاز فيزيائياً للمدير
            attemptNumber == 9 -> 6L * 60L * 60_000L    // 6 ساعات
            attemptNumber == 8 -> 60L * 60_000L         // ساعة واحدة
            attemptNumber == 7 -> 10L * 60_000L         // 10 دقائق
            attemptNumber == 6 -> 5L * 60_000L          // 5 دقائق
            attemptNumber == 5 -> 60_000L               // دقيقة واحدة
            attemptNumber == 3 -> 30_000L               // 30 ثانية
            else -> 0L                                  // المحاولات 1، 2، 4 تنبيه بدون حظر زمني
        }
    }

    data class LockoutSnapshot(
        val failedAttempts: Int,
        val remainingLockMs: Long,
        val permanentlyLocked: Boolean,
        val permanentReason: String
    )

    private val counterFile: File
        get() = File(context.noBackupFilesDir, COUNTER_FILE_NAME)

    private val tombstoneFile: File
        get() = File(context.noBackupFilesDir, TOMBSTONE_FILE_NAME)

    private val timeFile: File
        get() = File(context.noBackupFilesDir, TIME_FILE_NAME)

    private fun currentBootCount(): Int =
        try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1)
        } catch (_: Exception) {
            -1
        }

    @Synchronized
    fun initializeOnActivation(verifiedAdminTimestampMs: Long) {
        if (tombstoneFile.exists()) tombstoneFile.delete()
        CryptoEngine.destroyKeystoreKey(CryptoEngine.LOCKED_TOMBSTONE_AES_ALIAS)

        KioskPolicyManager.syncDeviceClockIfDeviceOwner(context, verifiedAdminTimestampMs)

        val rawWall = System.currentTimeMillis()
        val clockOffsetMs = max(0L, verifiedAdminTimestampMs - rawWall)
        val adjustedNow = rawWall + clockOffsetMs
        val nowElapsed = SystemClock.elapsedRealtime()
        val boot = currentBootCount()

        saveActiveCounter(
            failedAttempts = 0,
            remainingLockMs = 0L,
            lastElapsedAnchorMs = nowElapsed,
            bootCount = boot
        )

        saveTimeInternal(
            highWaterWallMs = adjustedNow,
            anchorWallMs = adjustedNow,
            anchorElapsedMs = nowElapsed,
            clockOffsetMs = clockOffsetMs,
            bootCount = boot
        )
    }

    @Synchronized
    fun inspectAndRefreshLockout(): LockoutSnapshot {
        if (tombstoneFile.exists()) {
            return readTombstoneOrDefault()
        }

        if (!counterFile.exists()) {
            return triggerPermanentLock("تم اكتشاف غياب أو حذف ملف عداد محاولات الدخول (تلاعب أمني)")
        }

        val json = try {
            val decrypted = CryptoEngine.decryptWithKeystore(
                context,
                counterFile.readBytes(),
                COUNTER_AAD,
                CryptoEngine.ACTIVE_COUNTER_AES_ALIAS
            )
            JSONObject(String(decrypted, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            return triggerPermanentLock("فشل التحقق من التوقيع التشفيري لملف عداد المحاولات أو محاولة استرجاع حالة قديمة")
        }

        val failedAttempts = json.optInt("failedAttempts", 0)
        var remainingLockMs = json.optLong("remainingLockMs", 0L)
        val lastElapsed = json.optLong("lastElapsedAnchorMs", 0L)
        val savedBoot = json.optInt("bootCount", -2)

        val nowElapsed = SystemClock.elapsedRealtime()
        val nowBoot = currentBootCount()
        val sameBootSession = (nowBoot != -1 && nowBoot == savedBoot && nowElapsed >= lastElapsed)

        if (remainingLockMs > 0L) {
            // إذا كان في نفس جلسة الإقلاع نخصم الزمن المنقضي؛ وعند إعادة التشغيل يستأنف المدة المتبقية كاملة دون تصفير!
            val delta = if (sameBootSession) (nowElapsed - lastElapsed) else 0L
            remainingLockMs = max(0L, remainingLockMs - delta)
            saveActiveCounter(failedAttempts, remainingLockMs, nowElapsed, nowBoot)
        } else if (!sameBootSession) {
            saveActiveCounter(failedAttempts, 0L, nowElapsed, nowBoot)
        }

        return LockoutSnapshot(failedAttempts, remainingLockMs, false, "")
    }

    @Synchronized
    fun recordFailedLoginAttempt(): LockoutSnapshot {
        val current = inspectAndRefreshLockout()
        if (current.permanentlyLocked) return current

        val nextAttempts = current.failedAttempts + 1
        val stepPenaltyMs = computePenaltyMsForAttempt(nextAttempts)

        if (stepPenaltyMs < 0L) {
            return triggerPermanentLock(
                "تجاوز الحد الأقصى لمحاولات تسجيل الدخول الفاشلة (10 محاولات). يجب نقل الجهاز فيزيائياً إلى المدير.",
                attemptsOverride = nextAttempts
            )
        }

        val effectivePenaltyMs = max(current.remainingLockMs, stepPenaltyMs)
        saveActiveCounter(
            failedAttempts = nextAttempts,
            remainingLockMs = effectivePenaltyMs,
            lastElapsedAnchorMs = SystemClock.elapsedRealtime(),
            bootCount = currentBootCount()
        )
        return LockoutSnapshot(nextAttempts, effectivePenaltyMs, false, "")
    }

    @Synchronized
    fun resetOnSuccessfulLogin() {
        if (tombstoneFile.exists()) return
        saveActiveCounter(
            failedAttempts = 0,
            remainingLockMs = 0L,
            lastElapsedAnchorMs = SystemClock.elapsedRealtime(),
            bootCount = currentBootCount()
        )
    }

    @Synchronized
    fun verifyMonotonicTimeAndExpiry(expiresAtEpochMs: Long): String? {
        val snap = inspectAndRefreshLockout()
        if (snap.permanentlyLocked) return snap.permanentReason

        if (!timeFile.exists()) {
            return triggerPermanentLock("غياب ملف حماية الوقت التصاعدي (تلاعب أمني)").permanentReason
        }

        val json = try {
            val decrypted = CryptoEngine.decryptWithKeystore(
                context,
                timeFile.readBytes(),
                TIME_AAD,
                CryptoEngine.MASTER_VAULT_AES_ALIAS
            )
            JSONObject(String(decrypted, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            return triggerPermanentLock("تلف التوقيع التشفيري لملف الوقت التصاعدي (تلاعب أمني)").permanentReason
        }

        val highWaterWallMs = json.getLong("highWaterWallMs")
        val anchorWallMs = json.getLong("anchorWallMs")
        val anchorElapsedMs = json.getLong("anchorElapsedMs")
        val clockOffsetMs = json.optLong("clockOffsetMs", 0L)
        val savedBoot = json.optInt("bootCount", -2)

        val adjustedWallMs = System.currentTimeMillis() + clockOffsetMs
        val nowElapsedMs = SystemClock.elapsedRealtime()
        val nowBoot = currentBootCount()

        // 1) كشف إرجاع ساعة الجهاز للوراء مقارنة بأعلى طابع زمني وصله الجهاز
        if (adjustedWallMs + CLOCK_ROLLBACK_TOLERANCE_MS < highWaterWallMs) {
            return triggerPermanentLock(
                "تم اكتشاف إرجاع أو تلاعب في ساعة الجهاز. توقف التطبيق نهائياً ويجب نقل الجهاز فيزيائياً إلى المدير."
            ).permanentReason
        }

        // 2) خلال نفس جلسة الإقلاع فقط (BOOT_COUNT متطابق): مقارنة تقدم ساعة الحائط مع ساعة المعالج الرتيبة
        var effectiveNowMs = adjustedWallMs
        if (nowBoot != -1 && nowBoot == savedBoot && nowElapsedMs >= anchorElapsedMs) {
            val expectedWallMs = anchorWallMs + (nowElapsedMs - anchorElapsedMs)
            if (abs(adjustedWallMs - expectedWallMs) > IN_BOOT_DRIFT_TOLERANCE_MS) {
                return triggerPermanentLock(
                    "تم رصد تغيير يدوي في وقت النظام أثناء التشغيل. توقف التطبيق نهائياً ويجب نقل الجهاز فيزيائياً إلى المدير."
                ).permanentReason
            }
            effectiveNowMs = max(adjustedWallMs, expectedWallMs)
        }

        // 3) فحص انتهاء صلاحية الترخيص
        if (effectiveNowMs >= expiresAtEpochMs) {
            return triggerPermanentLock(
                "انتهت صلاحية التطبيق الزمنية. توقف التطبيق نهائياً ويلزم نقل الجهاز فيزيائياً للإدارة للتجديد."
            ).permanentReason
        }

        saveTimeInternal(
            highWaterWallMs = max(highWaterWallMs, effectiveNowMs),
            anchorWallMs = adjustedWallMs,
            anchorElapsedMs = nowElapsedMs,
            clockOffsetMs = clockOffsetMs,
            bootCount = nowBoot
        )
        return null
    }

    @Synchronized
    fun triggerPermanentLock(reason: String, attemptsOverride: Int? = null): LockoutSnapshot {
        val attempts = attemptsOverride ?: 10

        CryptoEngine.destroyKeystoreKey(CryptoEngine.ACTIVE_COUNTER_AES_ALIAS)
        if (counterFile.exists()) counterFile.delete()

        val payload = JSONObject().apply {
            put("failedAttempts", attempts)
            put("permanentReason", reason)
        }.toString().toByteArray(StandardCharsets.UTF_8)

        val encrypted = CryptoEngine.encryptWithKeystore(
            context,
            payload,
            TOMBSTONE_AAD,
            CryptoEngine.LOCKED_TOMBSTONE_AES_ALIAS
        )
        writeAtomically(tombstoneFile, encrypted)

        return LockoutSnapshot(attempts, 0L, true, reason)
    }

    @Synchronized
    fun performPhysicalAdminReset(verifiedAdminTimestampMs: Long) {
        if (tombstoneFile.exists()) tombstoneFile.delete()
        CryptoEngine.destroyKeystoreKey(CryptoEngine.LOCKED_TOMBSTONE_AES_ALIAS)

        KioskPolicyManager.syncDeviceClockIfDeviceOwner(context, verifiedAdminTimestampMs)

        val rawWall = System.currentTimeMillis()
        val clockOffsetMs = max(0L, verifiedAdminTimestampMs - rawWall)
        val adjustedNow = rawWall + clockOffsetMs
        val elapsed = SystemClock.elapsedRealtime()
        val boot = currentBootCount()

        saveActiveCounter(
            failedAttempts = 0,
            remainingLockMs = 0L,
            lastElapsedAnchorMs = elapsed,
            bootCount = boot
        )
        saveTimeInternal(
            highWaterWallMs = adjustedNow,
            anchorWallMs = adjustedNow,
            anchorElapsedMs = elapsed,
            clockOffsetMs = clockOffsetMs,
            bootCount = boot
        )
    }

    private fun readTombstoneOrDefault(): LockoutSnapshot {
        return try {
            val dec = CryptoEngine.decryptWithKeystore(
                context,
                tombstoneFile.readBytes(),
                TOMBSTONE_AAD,
                CryptoEngine.LOCKED_TOMBSTONE_AES_ALIAS
            )
            val json = JSONObject(String(dec, StandardCharsets.UTF_8))
            LockoutSnapshot(
                failedAttempts = json.optInt("failedAttempts", 10),
                remainingLockMs = 0L,
                permanentlyLocked = true,
                permanentReason = json.optString(
                    "permanentReason",
                    "التطبيق مغلق نهائياً — يجب نقل الجهاز فيزيائياً للمدير."
                )
            )
        } catch (_: Exception) {
            LockoutSnapshot(
                failedAttempts = 10,
                remainingLockMs = 0L,
                permanentlyLocked = true,
                permanentReason = "تم اكتشاف عبث بسجل الإغلاق النهائي — يجب نقل الجهاز فيزيائياً للمدير."
            )
        }
    }

    private fun saveActiveCounter(
        failedAttempts: Int,
        remainingLockMs: Long,
        lastElapsedAnchorMs: Long,
        bootCount: Int
    ) {
        val payload = JSONObject().apply {
            put("failedAttempts", failedAttempts)
            put("remainingLockMs", remainingLockMs)
            put("lastElapsedAnchorMs", lastElapsedAnchorMs)
            put("bootCount", bootCount)
        }.toString().toByteArray(StandardCharsets.UTF_8)

        val encrypted = CryptoEngine.encryptWithKeystore(
            context,
            payload,
            COUNTER_AAD,
            CryptoEngine.ACTIVE_COUNTER_AES_ALIAS
        )
        writeAtomically(counterFile, encrypted)
    }

    private fun saveTimeInternal(
        highWaterWallMs: Long,
        anchorWallMs: Long,
        anchorElapsedMs: Long,
        clockOffsetMs: Long,
        bootCount: Int
    ) {
        val payload = JSONObject().apply {
            put("highWaterWallMs", highWaterWallMs)
            put("anchorWallMs", anchorWallMs)
            put("anchorElapsedMs", anchorElapsedMs)
            put("clockOffsetMs", clockOffsetMs)
            put("bootCount", bootCount)
        }.toString().toByteArray(StandardCharsets.UTF_8)

        val encrypted = CryptoEngine.encryptWithKeystore(
            context,
            payload,
            TIME_AAD,
            CryptoEngine.MASTER_VAULT_AES_ALIAS
        )
        writeAtomically(timeFile, encrypted)
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
