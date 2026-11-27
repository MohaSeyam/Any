package com.securedb.kiosk.ui

import android.os.Bundle

/**
 * موجه الإقلاع الأمني:
 * 1) إذا لم يُفعّل الجهاز بعد -> شاشة التفعيل اليدوي (ActivationActivity).
 * 2) إذا كان مغلقاً نهائياً أو تم التلاعب بالوقت/ملف العداد أو انتهت صلاحيته -> شاشة الإغلاق الإداري (AdminLockoutActivity).
 * 3) إذا كانت هناك جلسة نشطة ضمن مهلة الـ 15 دقيقة -> مستعرض البيانات (DatabaseBrowserActivity).
 * 4) خلاف ذلك -> شاشة تسجيل الدخول الإلزامية (LoginActivity).
 */
class LauncherActivity : BaseSecureActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (!secureApp.licenseManager.isActivated()) {
            navigateClearStack(ActivationActivity::class.java)
            return
        }

        val lockSnap = secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
        if (lockSnap.permanentlyLocked) {
            secureApp.terminateSession()
            navigateClearStack(AdminLockoutActivity::class.java)
            return
        }

        val timeOrExpiryErr = try {
            secureApp.lockoutAndTimeGuard.verifyMonotonicTimeAndExpiry(
                secureApp.licenseManager.getLicenseExpiryMs()
            )
        } catch (e: Exception) {
            e.message ?: "خطأ في التحقق من خزنة الترخيص"
        }

        if (timeOrExpiryErr != null) {
            secureApp.terminateSession()
            navigateClearStack(AdminLockoutActivity::class.java)
            return
        }

        if (secureApp.isSessionValidAndActive()) {
            navigateClearStack(DatabaseBrowserActivity::class.java)
        } else {
            navigateClearStack(LoginActivity::class.java)
        }
    }
}
