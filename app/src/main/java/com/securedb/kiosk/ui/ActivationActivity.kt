package com.securedb.kiosk.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.securedb.kiosk.databinding.ActivityActivationBinding
import com.securedb.kiosk.kiosk.KioskPolicyManager
import com.securedb.kiosk.security.CryptoEngine
import com.securedb.kiosk.security.SecurityConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ActivationActivity : BaseSecureActivity() {

    private lateinit var binding: ActivityActivationBinding

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        if (!result.contents.isNullOrBlank()) {
            binding.etLicenseToken.setText(result.contents.trim())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (secureApp.licenseManager.isActivated()) {
            navigateClearStack(LauncherActivity::class.java)
            return
        }

        binding = ActivityActivationBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.etLicenseToken.hint = "الصق مفتاح الترخيص الموقّع (LIC2....)"

        refreshRequestUi(null)

        binding.btnGenerateSampleDb.setOnClickListener {
            generateLabDatabase()
        }

        binding.btnCopyRequest.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(
                ClipData.newPlainText("ActivationRequest", binding.tvRequestCode.text.toString())
            )
            Toast.makeText(this, "تم نسخ المفتاح الأولي (محمي بـ RSA-OAEP)", Toast.LENGTH_SHORT).show()
        }

        binding.btnScanLicenseQr.setOnClickListener {
            val options = ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("وجّه الكاميرا نحو رمز QR للترخيص على شاشة الإدارة")
                setBeepEnabled(false)
                setOrientationLocked(true)
            }
            qrScannerLauncher.launch(options)
        }

        binding.btnActivateDevice.setOnClickListener {
            performActivation()
        }
    }

    private fun refreshRequestUi(labRawDekBytes: ByteArray?) {
        val reqInfo = secureApp.licenseManager.getOrCreateActivationRequest(labRawDekBytes)
        val dbFile = getDatabasePath(SecurityConfig.DATABASE_FILENAME)
        val dbSizeMb = if (dbFile.exists()) String.format("%.2f MB", dbFile.length() / (1024.0 * 1024.0)) else "0 MB"
        val ownerStatus = if (KioskPolicyManager.isDeviceOwner(this)) {
            "مفعّل (Device Owner Kiosk)"
        } else {
            "وضع التجريب القياسي (يمكن تفعيل Device Owner عبر ADB)"
        }

        binding.tvDeviceStatus.text = buildString {
            appendLine("معرّف عتاد الجهاز: ${reqInfo.deviceId}")
            appendLine("وضع إدارة الجهاز: $ownerStatus")
            if (reqInfo.dbProvisioned) {
                append("قاعدة البيانات المشفرة بالصور والمرفقات: جاهزة ($dbSizeMb)")
            } else {
                append("قاعدة البيانات المشفرة: غير موجودة — اضغط الزر أدناه لتوليد قاعدة تجريبية بالصور والـ PDF أو انقل قاعدة الـ 100GB")
            }
        }

        binding.tvRequestCode.text = reqInfo.requestCode
        binding.ivRequestQr.setImageBitmap(QrHelper.generateQrBitmap(reqInfo.requestCode, 520))
    }

    private fun generateLabDatabase() {
        binding.btnGenerateSampleDb.isEnabled = false
        binding.progressActivation.visibility = View.VISIBLE
        binding.tvActivationFeedback.setTextColor(0xFF1E3A8A.toInt())
        binding.tvActivationFeedback.text =
            "جاري إنشاء وتشفير قاعدة البيانات مع صور عالية الدقة (>2.7MB) ومستندات PDF وفهرس FTS5..."

        lifecycleScope.launch {
            try {
                val rawDekBytes = withContext(Dispatchers.IO) {
                    secureApp.dbEngine.generateLabSampleEncryptedDatabase(sampleRowCount = 250)
                }
                refreshRequestUi(rawDekBytes)
                binding.tvActivationFeedback.setTextColor(0xFF0F766E.toInt())
                binding.tvActivationFeedback.text =
                    "تم إنشاء القاعدة المشفرة بالصور والمرفقات وتغليف مفتاحها بـ RSA-OAEP داخل Keystore! انسخ المفتاح الأولي الجديد لأداة الإدارة."
            } catch (e: Exception) {
                binding.tvActivationFeedback.setTextColor(0xFFB91C1C.toInt())
                binding.tvActivationFeedback.text = "خطأ أثناء إنشاء القاعدة: ${e.message}"
            } finally {
                binding.progressActivation.visibility = View.GONE
                binding.btnGenerateSampleDb.isEnabled = true
            }
        }
    }

    private fun performActivation() {
        val dbFile = getDatabasePath(SecurityConfig.DATABASE_FILENAME)
        if (!dbFile.exists() || dbFile.length() == 0L) {
            binding.tvActivationFeedback.setTextColor(0xFFB91C1C.toInt())
            binding.tvActivationFeedback.text = "يجب إنشاء أو نقل قاعدة البيانات المشفرة أولاً قبل التفعيل!"
            return
        }

        val licenseToken = binding.etLicenseToken.text.toString().trim()
        val adminPassChars = CharArray(binding.etAdminPassword.length()).also {
            binding.etAdminPassword.text.getChars(0, it.size, it, 0)
        }
        val username = binding.etUsername.text.toString().trim()
        val userPassChars = CharArray(binding.etUserPassword.length()).also {
            binding.etUserPassword.text.getChars(0, it.size, it, 0)
        }
        val sealAdb = binding.cbSealAdb.isChecked

        binding.btnActivateDevice.isEnabled = false
        binding.progressActivation.visibility = View.VISIBLE
        binding.tvActivationFeedback.setTextColor(0xFF1E3A8A.toInt())
        binding.tvActivationFeedback.text =
            "جاري التحقق من توقيع Ed25519 وفك تغليف RSA-OAEP واشتقاق Argon2id..."

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.Default) {
                    val verified = secureApp.licenseManager.verifyLicenseAndAdminPassword(
                        licenseToken = licenseToken,
                        adminPassword = adminPassChars
                    )
                    secureApp.licenseManager.completeActivationWithUserCredentials(
                        verifiedLicense = verified,
                        username = username,
                        userPassword = userPassChars
                    )
                }

                // تطهير الحافظة المؤقتة (Clipboard) من أي رموز تفعيل بعد اكتمال التفعيل
                clearClipboardSafely()

                KioskPolicyManager.applyKioskRestrictions(this@ActivationActivity, sealAdb = sealAdb)
                Toast.makeText(
                    this@ActivationActivity,
                    "تم تفعيل الجهاز بنجاح وتهيئة عداد الأمان (= 0)",
                    Toast.LENGTH_LONG
                ).show()
                navigateClearStack(LoginActivity::class.java)
            } catch (e: Exception) {
                binding.tvActivationFeedback.setTextColor(0xFFB91C1C.toInt())
                binding.tvActivationFeedback.text = e.message ?: "فشل التفعيل"
            } finally {
                CryptoEngine.zeroizeChars(adminPassChars, userPassChars)
                binding.progressActivation.visibility = View.GONE
                binding.btnActivateDevice.isEnabled = true
            }
        }
    }

    private fun clearClipboardSafely() {
        try {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (_: Exception) {
        }
    }
}
