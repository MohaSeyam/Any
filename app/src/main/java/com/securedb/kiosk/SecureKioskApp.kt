package com.securedb.kiosk

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.securedb.kiosk.db.SecureReadOnlyDbEngine
import com.securedb.kiosk.security.LicenseAndAuthManager
import com.securedb.kiosk.security.LockoutAndTimeGuard
import com.securedb.kiosk.security.SecurityConfig

class SecureKioskApp : Application(), DefaultLifecycleObserver {

    lateinit var lockoutAndTimeGuard: LockoutAndTimeGuard
        private set

    lateinit var licenseManager: LicenseAndAuthManager
        private set

    lateinit var dbEngine: SecureReadOnlyDbEngine
        private set

    @Volatile
    var activeUsername: String? = null
        private set

    @Volatile
    private var backgroundEnteredAtElapsedMs: Long = -1L

    @Volatile
    private var lastUserInteractionElapsedMs: Long = 0L

    override fun onCreate() {
        super<Application>.onCreate()
        lockoutAndTimeGuard = LockoutAndTimeGuard(this)
        licenseManager = LicenseAndAuthManager(this, lockoutAndTimeGuard)
        dbEngine = SecureReadOnlyDbEngine(this)

        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    @Synchronized
    fun onLoginSucceeded(username: String, rawDekBytes: ByteArray) {
        dbEngine.openReadOnly(rawDekBytes)
        activeUsername = username.trim()
        backgroundEnteredAtElapsedMs = -1L
        lastUserInteractionElapsedMs = SystemClock.elapsedRealtime()
    }

    /**
     * يحدث وقت التفاعل فقط إذا كانت الجلسة لا تزال ضمن مهلة الـ 15 دقيقة؛
     * وإذا كانت قد انتهت بالفعل ينهي الجلسة فوراً ولا يسمح بإحيائها باللمس!
     */
    @Synchronized
    fun recordUserInteraction() {
        if (activeUsername == null) return
        val now = SystemClock.elapsedRealtime()

        if (backgroundEnteredAtElapsedMs > 0L &&
            (now - backgroundEnteredAtElapsedMs) > SecurityConfig.SESSION_GRACE_PERIOD_MS
        ) {
            terminateSession()
            return
        }

        if (lastUserInteractionElapsedMs > 0L &&
            (now - lastUserInteractionElapsedMs) > SecurityConfig.SESSION_GRACE_PERIOD_MS
        ) {
            terminateSession()
            return
        }

        lastUserInteractionElapsedMs = now
    }

    @Synchronized
    fun isSessionValidAndActive(): Boolean {
        if (activeUsername == null || !dbEngine.isOpen()) return false

        val nowElapsed = SystemClock.elapsedRealtime()
        if (backgroundEnteredAtElapsedMs > 0L &&
            (nowElapsed - backgroundEnteredAtElapsedMs) > SecurityConfig.SESSION_GRACE_PERIOD_MS
        ) {
            terminateSession()
            return false
        }

        if (lastUserInteractionElapsedMs > 0L &&
            (nowElapsed - lastUserInteractionElapsedMs) > SecurityConfig.SESSION_GRACE_PERIOD_MS
        ) {
            terminateSession()
            return false
        }

        val expiryError = try {
            lockoutAndTimeGuard.verifyMonotonicTimeAndExpiry(licenseManager.getLicenseExpiryMs())
        } catch (e: Exception) {
            e.message ?: "خطأ في التحقق من الترخيص"
        }
        if (expiryError != null) {
            terminateSession()
            return false
        }

        return true
    }

    @Synchronized
    fun terminateSession() {
        activeUsername = null
        backgroundEnteredAtElapsedMs = -1L
        lastUserInteractionElapsedMs = 0L
        dbEngine.closeSession()
    }

    override fun onStop(owner: LifecycleOwner) {
        if (activeUsername != null) {
            backgroundEnteredAtElapsedMs = SystemClock.elapsedRealtime()
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        if (activeUsername != null && backgroundEnteredAtElapsedMs > 0L) {
            val bgDuration = SystemClock.elapsedRealtime() - backgroundEnteredAtElapsedMs
            if (bgDuration > SecurityConfig.SESSION_GRACE_PERIOD_MS) {
                terminateSession()
            } else {
                backgroundEnteredAtElapsedMs = -1L
            }
        }
    }
}
