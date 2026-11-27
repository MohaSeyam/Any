package com.securedb.kiosk.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.view.View
import androidx.lifecycle.lifecycleScope
import com.securedb.kiosk.databinding.ActivityAttachmentViewerBinding
import com.securedb.kiosk.security.CryptoEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets
import java.util.Locale
import kotlin.math.max
import kotlin.math.min

class SecureAttachmentViewerActivity : BaseSecureActivity() {

    companion object {
        const val EXTRA_ATTACHMENT_ID = "extra_attachment_id"
        private const val MAX_DECODE_DIMENSION_PX = 2048
        private const val MAX_TEXT_PREVIEW_BYTES = 1 * 1024 * 1024 // 1 MB
    }

    override val requiresAuthenticatedSession: Boolean = true

    private lateinit var binding: ActivityAttachmentViewerBinding

    private val pdfMutex = Mutex()
    private var activeBitmap: Bitmap? = null
    private var pdfDescriptor: ParcelFileDescriptor? = null
    private var pdfRenderer: PdfRenderer? = null
    private var totalPdfPages = 0
    private var currentPdfPageIndex = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!enforceActiveSessionOrRedirect()) return

        binding = ActivityAttachmentViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.viewerWatermark.setWatermarkInfo(
            secureApp.activeUsername ?: "User",
            secureApp.licenseManager.getDeviceId()
        )

        binding.btnCloseViewer.setOnClickListener {
            finish()
        }

        binding.btnPrevPdfPage.setOnClickListener {
            if (currentPdfPageIndex > 0) {
                renderPdfPageAsync(currentPdfPageIndex - 1)
            }
        }

        binding.btnNextPdfPage.setOnClickListener {
            if (currentPdfPageIndex + 1 < totalPdfPages) {
                renderPdfPageAsync(currentPdfPageIndex + 1)
            }
        }

        val attachmentId = intent.getLongExtra(EXTRA_ATTACHMENT_ID, -1L)
        if (attachmentId <= 0L) {
            finish()
            return
        }

        streamAndDisplayAttachment(attachmentId)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::binding.isInitialized) {
            binding.zoomableImageView.setImageDrawable(null)
            binding.tvDocumentContent.text = ""
        }
        activeBitmap?.let {
            if (!it.isRecycled) it.recycle()
        }
        activeBitmap = null

        val rendererToClose = pdfRenderer
        val descriptorToClose = pdfDescriptor
        pdfRenderer = null
        pdfDescriptor = null

        kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            withContext(NonCancellable) {
                pdfMutex.withLock {
                    try {
                        rendererToClose?.close()
                    } catch (_: Exception) {
                    }
                    try {
                        descriptorToClose?.close()
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    private fun streamAndDisplayAttachment(attachmentId: Long) {
        binding.progressViewer.visibility = View.VISIBLE
        binding.tvViewerIntegrityStatus.text = "جاري البث المشفر والتحقق من بصمة SHA-256..."

        lifecycleScope.launch {
            try {
                val meta = withContext(Dispatchers.IO) {
                    secureApp.dbEngine.getAttachmentMetaById(attachmentId)
                } ?: throw IllegalStateException("المرفق غير موجود")

                binding.tvViewerTitle.text = "${meta.fileName} (${formatSize(meta.sizeBytes)})"

                when {
                    meta.mimeType.startsWith("image/") -> {
                        val decodedBmp = withContext(Dispatchers.IO) {
                            val rawBytes = secureApp.dbEngine.readAttachmentToMemoryVerified(
                                attachmentId = meta.id,
                                expectedSha256Hex = meta.sha256Hex
                            )
                            try {
                                decodeDownsampledBitmapInMemory(rawBytes)
                            } finally {
                                CryptoEngine.zeroize(rawBytes)
                            }
                        } ?: throw IllegalStateException("تعذر فك ترميز الصورة")

                        replaceActiveBitmap(decodedBmp)
                        binding.progressViewer.visibility = View.GONE
                        binding.zoomableImageView.visibility = View.VISIBLE
                        binding.zoomableImageView.setSecureBitmap(decodedBmp)
                        binding.tvViewerIntegrityStatus.text =
                            "✓ تم التحقق من SHA-256 بالذاكرة (استخدم إصبعين للتكبير والنقر المزدوج للإعادة)"
                    }

                    meta.mimeType == "application/pdf" -> {
                        val pagesCount = withContext(Dispatchers.IO) {
                            pdfMutex.withLock {
                                val pfd = secureApp.dbEngine.openVerifiedUnlinkedPdfDescriptor(
                                    attachmentId = meta.id,
                                    expectedSha256Hex = meta.sha256Hex
                                )
                                try {
                                    val renderer = PdfRenderer(pfd)
                                    pdfDescriptor = pfd
                                    pdfRenderer = renderer
                                    renderer.pageCount
                                } catch (t: Throwable) {
                                    try {
                                        pfd.close()
                                    } catch (_: Exception) {
                                    }
                                    throw t
                                }
                            }
                        }
                        totalPdfPages = pagesCount
                        binding.progressViewer.visibility = View.GONE
                        binding.zoomableImageView.visibility = View.VISIBLE
                        binding.pdfControlsBar.visibility = View.VISIBLE
                        binding.tvViewerIntegrityStatus.text =
                            "✓ تم التحقق من SHA-256 (عارض PDF داخلي محذوف الرابط من القرص)"
                        renderPdfPageAsync(0)
                    }

                    isSupportedTextMime(meta.mimeType) -> {
                        val textContent = withContext(Dispatchers.IO) {
                            val rawBytes = secureApp.dbEngine.readAttachmentToMemoryVerified(
                                attachmentId = meta.id,
                                expectedSha256Hex = meta.sha256Hex,
                                maxAllowedBytes = MAX_TEXT_PREVIEW_BYTES
                            )
                            try {
                                String(rawBytes, StandardCharsets.UTF_8)
                            } finally {
                                CryptoEngine.zeroize(rawBytes)
                            }
                        }
                        binding.progressViewer.visibility = View.GONE
                        binding.scrollTextViewer.visibility = View.VISIBLE
                        binding.tvDocumentContent.text = textContent
                        binding.tvViewerIntegrityStatus.text =
                            "✓ تم التحقق من SHA-256 وعرض المستند بالذاكرة العشوائية"
                    }

                    else -> {
                        throw IllegalArgumentException(
                            "نوع المرفق الثنائي (${meta.mimeType}) لا يُعرض نصياً؛ يدعم العارض الداخلي الصور وملفات PDF والمستندات النصية."
                        )
                    }
                }
            } catch (e: Exception) {
                binding.progressViewer.visibility = View.GONE
                binding.tvViewerIntegrityStatus.setTextColor(Color.rgb(248, 113, 113))
                binding.tvViewerIntegrityStatus.text = "تنبيه: ${e.message}"
            }
        }
    }

    private fun renderPdfPageAsync(pageIndex: Int) {
        binding.btnPrevPdfPage.isEnabled = false
        binding.btnNextPdfPage.isEnabled = false

        lifecycleScope.launch {
            val rendered = withContext(Dispatchers.IO) {
                pdfMutex.withLock {
                    val renderer = pdfRenderer ?: return@withLock null
                    if (pageIndex !in 0 until renderer.pageCount) return@withLock null

                    renderer.openPage(pageIndex).use { page ->
                        val rawW = (page.width * 2).coerceAtLeast(1)
                        val rawH = (page.height * 2).coerceAtLeast(1)
                        val clampScale = min(
                            1f,
                            MAX_DECODE_DIMENSION_PX.toFloat() / max(rawW, rawH).toFloat()
                        )
                        val targetW = (rawW * clampScale).toInt().coerceAtLeast(1)
                        val targetH = (rawH * clampScale).toInt().coerceAtLeast(1)

                        val bmp = Bitmap.createBitmap(targetW, targetH, Bitmap.Config.ARGB_8888)
                        bmp.eraseColor(Color.WHITE)
                        page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        bmp
                    }
                }
            } ?: return@launch

            currentPdfPageIndex = pageIndex
            replaceActiveBitmap(rendered)
            binding.zoomableImageView.setSecureBitmap(rendered)
            binding.tvPdfPageIndicator.text = "صفحة ${pageIndex + 1} من $totalPdfPages"
            binding.btnPrevPdfPage.isEnabled = pageIndex > 0
            binding.btnNextPdfPage.isEnabled = (pageIndex + 1) < totalPdfPages
        }
    }

    private fun isSupportedTextMime(mime: String): Boolean {
        val m = mime.lowercase(Locale.US)
        return m.startsWith("text/") || m == "application/json" || m == "application/xml"
    }

    private fun decodeDownsampledBitmapInMemory(bytes: ByteArray): Bitmap? {
        val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, boundsOpts)

        var sampleSize = 1
        val maxSide = max(boundsOpts.outWidth, boundsOpts.outHeight)
        while (maxSide / sampleSize > MAX_DECODE_DIMENSION_PX) {
            sampleSize *= 2
        }

        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts)
    }

    private fun replaceActiveBitmap(newBmp: Bitmap) {
        val old = activeBitmap
        activeBitmap = newBmp
        if (old != null && old != newBmp && !old.isRecycled) {
            binding.zoomableImageView.setImageDrawable(null)
            old.recycle()
        }
    }

    private fun formatSize(bytes: Long): String {
        val mb = bytes / (1024.0 * 1024.0)
        return when {
            mb >= 1.0 -> String.format(Locale.US, "%.2f MB", mb)
            bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }
}
