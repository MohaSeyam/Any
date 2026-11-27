package com.securedb.kiosk.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.securedb.kiosk.databinding.ActivityAdminLockoutBinding
import com.securedb.kiosk.security.CryptoEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * شاشة الإغلاق النهائي:
 * تظهر عند استنفاد المحاولات الـ 10 أو حذف/تعديل ملف العداد أو التلاعب بالوقت أو انتهاء الصلاحية.
 * لا يُفتح الجهاز إلا بنقله فيزيائياً للمدير وتوقيع تحدٍّ لحظي بـ Ed25519 مع إدخال كلمة مرور المدير يدوياً.
 */
class AdminLockoutActivity : BaseSecureActivity() {

    private lateinit var binding: ActivityAdminLockoutBinding

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        if (!result.contents.isNullOrBlank()) {
            binding.etUnlockToken.setText(result.contents.trim())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureApp.terminateSession()

        binding = ActivityAdminLockoutBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.etUnlockToken.hint = "أمر الفتح الموقّع من حاسوب المدير (UNLK2....)"

        val snap = secureApp.lockoutAndTimeGuard.inspectAndRefreshLockout()
        binding.tvPermanentLockReason.text = snap.permanentReason.ifBlank {
            "توقف التطبيق لأسباب أمنية — يلزم فحص الجهاز فيزيائياً لدى المدير."
        }

        refreshUnlockChallenge()

        binding.btnCopyUnlockChallenge.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(
                ClipData.newPlainText("UnlockChallenge", binding.tvUnlockChallengeCode.text.toString())
            )
            Toast.makeText(this, "تم نسخ كود التحدي الحضوري", Toast.LENGTH_SHORT).show()
        }

        binding.btnScanUnlockQr.setOnClickListener {
            val options = ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("امسح أمر الفتح الموقّع من شاشة حاسوب المدير")
                setBeepEnabled(false)
                setOrientationLocked(true)
            }
            qrScannerLauncher.launch(options)
        }

        binding.btnExecuteAdminUnlock.setOnClickListener {
            executePhysicalUnlock()
        }
    }

    private fun refreshUnlockChallenge() {
        val challengeCode = secureApp.licenseManager.generatePhysicalUnlockChallenge()
        binding.tvUnlockChallengeCode.text = challengeCode
        binding.ivUnlockChallengeQr.setImageBitmap(QrHelper.generateQrBitmap(challengeCode, 480))
    }

    private fun executePhysicalUnlock() {
        val unlockToken = binding.etUnlockToken.text.toString().trim()
        val adminPassChars = CharArray(binding.etUnlockAdminPassword.length()).also {
            binding.etUnlockAdminPassword.text.getChars(0, it.size, it, 0)
        }

        if (unlockToken.isEmpty() || adminPassChars.isEmpty()) {
            CryptoEngine.zeroizeChars(adminPassChars)
            binding.tvUnlockFeedback.text = "يجب إدخال أمر الفتح الموقّع وكلمة مرور المدير معاً"
            return
        }

        binding.btnExecuteAdminUnlock.isEnabled = false
        binding.progressUnlock.visibility = View.VISIBLE
        binding.tvUnlockFeedback.text = "جاري التحقق من توقيع المدير (Ed25519 + Argon2id)..."

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.Default) {
                    secureApp.licenseManager.verifyPhysicalAdminUnlock(unlockToken, adminPassChars)
                }
                Toast.makeText(
                    this@AdminLockoutActivity,
                    "تم إعادة تنشيط الجهاز وتصفير العداد بنجاح بمعرفة المدير",
                    Toast.LENGTH_LONG
                ).show()
                navigateClearStack(LoginActivity::class.java)
            } catch (e: Exception) {
                binding.tvUnlockFeedback.text = e.message ?: "فشل الفتح الإداري"
                refreshUnlockChallenge()
            } finally {
                CryptoEngine.zeroizeChars(adminPassChars)
                binding.etUnlockAdminPassword.text?.clear()
                binding.progressUnlock.visibility = View.GONE
                binding.btnExecuteAdminUnlock.isEnabled = true
            }
        }
    }
}
