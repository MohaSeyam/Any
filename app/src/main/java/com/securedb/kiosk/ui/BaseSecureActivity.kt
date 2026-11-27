package com.securedb.kiosk.ui

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.AttributeSet
import android.view.View
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.securedb.kiosk.SecureKioskApp
import com.securedb.kiosk.kiosk.KioskPolicyManager
import com.securedb.kiosk.security.AppSelfProtection

abstract class BaseSecureActivity : AppCompatActivity() {

    protected val secureApp: SecureKioskApp
        get() = application as SecureKioskApp

    /**
     * تفعل الشاشات المحمية بعد تسجيل الدخول هذا المؤشر ليتم التحقق تلقائياً كل 5 ثوانٍ
     * من مهلة الـ 15 دقيقة وسلامة الوقت وصلاحية الترخيص.
     */
    protected open val requiresAuthenticatedSession: Boolean = false

    private val watchdogHandler = Handler(Looper.getMainLooper())
    private val globalSessionWatchdog = object : Runnable {
        override fun run() {
            if (!requiresAuthenticatedSession) return
            if (!enforceActiveSessionOrRedirect()) return
            watchdogHandler.postDelayed(this, 5_000L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        super.onCreate(savedInstanceState)
        window.decorView.layoutDirection = View.LAYOUT_DIRECTION_RTL

        // السماح بالرجوع بين الشاشات الفرعية داخل التطبيق، مع حظر الخروج من الشاشة الجذرية لوضع الكشك
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (!isTaskRoot) {
                    finish()
                }
            }
        })
    }

    override fun onResume() {
        super.onResume()
        KioskPolicyManager.enterKioskLockTaskIfPermitted(this)

        val integrity = AppSelfProtection.evaluateEnvironment(this)
        if (!integrity.passed && secureApp.licenseManager.isActivated() && this !is AdminLockoutActivity) {
            val reason = integrity.findings.joinToString(" | ")
            secureApp.terminateSession()
            secureApp.lockoutAndTimeGuard.triggerPermanentLock(reason)
            navigateClearStack(AdminLockoutActivity::class.java)
            return
        }

        if (requiresAuthenticatedSession) {
            if (enforceActiveSessionOrRedirect()) {
                watchdogHandler.removeCallbacks(globalSessionWatchdog)
                watchdogHandler.postDelayed(globalSessionWatchdog, 5_000L)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        watchdogHandler.removeCallbacks(globalSessionWatchdog)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        secureApp.recordUserInteraction()
    }

    protected fun enforceActiveSessionOrRedirect(): Boolean {
        val lockSnap = secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
        if (lockSnap.permanentlyLocked) {
            secureApp.terminateSession()
            navigateClearStack(AdminLockoutActivity::class.java)
            return false
        }
        if (!secureApp.isSessionValidAndActive()) {
            val recheck = secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
            if (recheck.permanentlyLocked) {
                navigateClearStack(AdminLockoutActivity::class.java)
            } else {
                navigateClearStack(LoginActivity::class.java)
            }
            return false
        }
        return true
    }

    protected fun navigateClearStack(target: Class<*>) {
        val intent = Intent(this, target).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        startActivity(intent)
        finish()
    }
}

object QrHelper {
    fun generateQrBitmap(content: String, sizePx: Int = 512): Bitmap {
        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.MARGIN to 1
        )
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.RGB_565)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bmp.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bmp
    }
}

class WatermarkOverlayView @JvmOverloads constructor(
    context: android.content.Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private var watermarkText: String = "مقيد — للقراءة فقط"

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.argb(28, 15, 23, 42)
        textSize = 36f
        isFakeBoldText = true
    }

    fun setWatermarkInfo(username: String, deviceId: String) {
        watermarkText = "$username  •  $deviceId  •  للقراءة فقط"
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.save()
        canvas.rotate(-28f, width / 2f, height / 2f)
        val stepX = 520f
        val stepY = 220f
        var y = -height.toFloat()
        while (y < height * 2f) {
            var x = -width.toFloat()
            while (x < width * 2f) {
                canvas.drawText(watermarkText, x, y, paint)
                x += stepX
            }
            y += stepY
        }
        canvas.restore()
    }
}
