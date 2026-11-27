package com.securedb.kiosk.ui

import android.os.Bundle
import android.os.CountDownTimer
import android.view.View
import androidx.lifecycle.lifecycleScope
import com.securedb.kiosk.databinding.ActivityLoginBinding
import com.securedb.kiosk.security.CryptoEngine
import com.securedb.kiosk.security.InvalidCredentialsException
import com.securedb.kiosk.security.PermanentLockException
import com.securedb.kiosk.security.TemporaryLockException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LoginActivity : BaseSecureActivity() {

    private lateinit var binding: ActivityLoginBinding
    private var lockTimer: CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.tvLoginDeviceBadge.text = "الجهاز: ${secureApp.licenseManager.getDeviceId()} • بدون إنترنت"

        binding.btnLogin.setOnClickListener {
            attemptLogin()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshSecurityState()
    }

    override fun onPause() {
        super.onPause()
        lockTimer?.cancel()
    }

    private fun refreshSecurityState() {
        val snap = secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
        if (snap.permanentlyLocked) {
            navigateClearStack(AdminLockoutActivity::class.java)
            return
        }

        val timeErr = try {
            secureApp.lockoutAndTimeGuard.verifyMonotonicTimeAndExpiry(
                secureApp.licenseManager.getLicenseExpiryMs()
            )
        } catch (e: Exception) {
            e.message ?: "تلاعب في خزنة الترخيص"
        }

        if (timeErr != null) {
            navigateClearStack(AdminLockoutActivity::class.java)
            return
        }

        binding.tvAttemptsCounter.text = "عداد المحاولات الفاشلة المسجل: ${snap.failedAttempts} من 10"

        if (snap.remainingLockMs > 0L) {
            startPenaltyCountdown(snap.remainingLockMs)
        } else {
            binding.tvLockCountdown.visibility = View.GONE
            binding.btnLogin.isEnabled = true
            binding.etLoginUsername.isEnabled = true
            binding.etLoginPassword.isEnabled = true
        }
    }

    private fun startPenaltyCountdown(durationMs: Long) {
        lockTimer?.cancel()
        binding.tvLockCountdown.visibility = View.VISIBLE
        binding.btnLogin.isEnabled = false
        binding.etLoginUsername.isEnabled = false
        binding.etLoginPassword.isEnabled = false

        lockTimer = object : CountDownTimer(durationMs, 1000L) {
            override fun onTick(millisUntilFinished: Long) {
                // تحديث الزمن المتبقي في التخزين المشفر دورياً لضمان عدم ضياع التقدم عند إعادة التشغيل
                secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
                binding.tvLockCountdown.text =
                    "التطبيق مقفل مؤقتاً: يرجى الانتظار ${formatDuration(millisUntilFinished)}"
            }

            override fun onFinish() {
                refreshSecurityState()
            }
        }.start()
    }

    private fun attemptLogin() {
        val username = binding.etLoginUsername.text.toString().trim()
        val passChars = CharArray(binding.etLoginPassword.length()).also {
            binding.etLoginPassword.text.getChars(0, it.size, it, 0)
        }

        if (username.isEmpty() || passChars.isEmpty()) {
            CryptoEngine.zeroizeChars(passChars)
            binding.tvLoginError.text = "يرجى إدخال اسم المستخدم وكلمة المرور"
            return
        }

        binding.btnLogin.isEnabled = false
        binding.progressLogin.visibility = View.VISIBLE
        binding.tvLoginError.text = ""

        lifecycleScope.launch {
            val authResult = withContext(Dispatchers.Default) {
                try {
                    secureApp.licenseManager.authenticateUserAndUnwrapDbKey(username, passChars)
                } finally {
                    CryptoEngine.zeroizeChars(passChars)
                }
            }

            binding.progressLogin.visibility = View.GONE
            binding.etLoginPassword.text?.clear()

            authResult.fold(
                onSuccess = { rawDek ->
                    try {
                        secureApp.onLoginSucceeded(username, rawDek)
                        navigateClearStack(DatabaseBrowserActivity::class.java)
                    } catch (e: Exception) {
                        CryptoEngine.zeroize(rawDek)
                        binding.tvLoginError.text = "خطأ في فتح قاعدة البيانات المشفرة: ${e.message}"
                        binding.btnLogin.isEnabled = true
                    }
                },
                onFailure = { err ->
                    when (err) {
                        is PermanentLockException -> {
                            navigateClearStack(AdminLockoutActivity::class.java)
                        }
                        is TemporaryLockException -> {
                            binding.tvLoginError.text =
                                "بيانات الدخول خاطئة (المحاولة ${err.attempts}/10) — تم تفعيل الحظر الزمني!"
                            refreshSecurityState()
                        }
                        is InvalidCredentialsException -> {
                            binding.tvLoginError.text = err.message
                            binding.btnLogin.isEnabled = true
                            refreshSecurityState()
                        }
                        else -> {
                            binding.tvLoginError.text = err.message ?: "فشل تسجيل الدخول"
                            binding.btnLogin.isEnabled = true
                            refreshSecurityState()
                        }
                    }
                }
            )
        }
    }

    private fun formatDuration(ms: Long): String {
        val totalSec = (ms + 999L) / 1000L
        val hours = totalSec / 3600L
        val minutes = (totalSec % 3600L) / 60L
        val seconds = totalSec % 60L
        return when {
            hours > 0 -> String.format("%02d ساعة و %02d دقيقة و %02d ثانية", hours, minutes, seconds)
            minutes > 0 -> String.format("%02d دقيقة و %02d ثانية", minutes, seconds)
            else -> "$seconds ثانية"
        }
    }
}
