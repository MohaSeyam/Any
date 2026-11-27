package com.securedb.kiosk.ui

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import androidx.lifecycle.lifecycleScope
import com.securedb.kiosk.databinding.ActivityRecordDetailBinding
import com.securedb.kiosk.databinding.ItemAttachmentRowBinding
import com.securedb.kiosk.db.SecureReadOnlyDbEngine
import com.securedb.kiosk.security.CryptoEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

class RecordDetailActivity : BaseSecureActivity() {

    companion object {
        const val EXTRA_RECORD_ID = "extra_record_id"
    }

    override val requiresAuthenticatedSession: Boolean = true

    private lateinit var binding: ActivityRecordDetailBinding
    private val decodedThumbnails = mutableListOf<Bitmap>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!enforceActiveSessionOrRedirect()) return

        binding = ActivityRecordDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.detailWatermark.setWatermarkInfo(
            secureApp.activeUsername ?: "User",
            secureApp.licenseManager.getDeviceId()
        )

        binding.btnBackToList.setOnClickListener {
            finish()
        }

        val recordId = intent.getLongExtra(EXTRA_RECORD_ID, -1L)
        if (recordId <= 0L) {
            finish()
            return
        }
        loadRecordAndAttachments(recordId)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::binding.isInitialized) {
            binding.containerAttachments.removeAllViews()
        }
        decodedThumbnails.forEach { bmp ->
            if (!bmp.isRecycled) bmp.recycle()
        }
        decodedThumbnails.clear()
    }

    private fun loadRecordAndAttachments(recordId: Long) {
        lifecycleScope.launch {
            val data = withContext(Dispatchers.IO) {
                val rec = secureApp.dbEngine.getRecordById(recordId)
                val atts = if (rec != null) secureApp.dbEngine.getAttachmentsForRecord(recordId) else emptyList()
                rec to atts
            }

            val record = data.first
            if (record == null) {
                finish()
                return@launch
            }

            binding.tvDetailHeaderCode.text = record.code
            binding.tvDetailClassification.text = record.classification
            binding.tvDetailTitle.text = record.title
            binding.tvDetailCategory.text = record.category
            binding.tvDetailBody.text = record.details

            val attachments = data.second
            binding.containerAttachments.removeAllViews()
            if (attachments.isEmpty()) {
                binding.tvAttachmentsSectionTitle.text = "لا توجد صور أو مرفقات مرتبطة بهذا السجل."
                return@launch
            }

            binding.tvAttachmentsSectionTitle.text =
                "الصور والمرفقات المشفرة (${attachments.size}) — تُفك بالذاكرة مع فحص SHA-256:"

            val inflater = LayoutInflater.from(this@RecordDetailActivity)
            for (att in attachments) {
                val row = ItemAttachmentRowBinding.inflate(inflater, binding.containerAttachments, false)
                row.tvAttFileName.text = att.fileName
                row.tvAttDescription.text = att.description
                row.tvAttMetaInfo.text =
                    "${att.mimeType} • ${formatSize(att.sizeBytes)} • SHA256:${att.sha256Hex.take(12)}..."

                val thumbBytes = att.thumbnailBytes
                val thumbBmp = if (thumbBytes != null && thumbBytes.isNotEmpty()) {
                    try {
                        BitmapFactory.decodeByteArray(thumbBytes, 0, thumbBytes.size)
                    } finally {
                        CryptoEngine.zeroize(thumbBytes)
                    }
                } else {
                    null
                }

                if (thumbBmp != null) {
                    decodedThumbnails.add(thumbBmp)
                    row.ivAttachmentThumb.setImageBitmap(thumbBmp)
                } else {
                    row.ivAttachmentThumb.setBackgroundColor(
                        if (att.mimeType == "application/pdf") Color.rgb(185, 28, 28) else Color.rgb(30, 58, 138)
                    )
                    row.ivAttachmentThumb.setImageResource(android.R.drawable.ic_menu_agenda)
                }

                row.root.setOnClickListener {
                    openAttachmentViewer(att)
                }
                binding.containerAttachments.addView(row.root)
            }
        }
    }

    private fun openAttachmentViewer(att: SecureReadOnlyDbEngine.AttachmentMeta) {
        val i = Intent(this, SecureAttachmentViewerActivity::class.java).apply {
            putExtra(SecureAttachmentViewerActivity.EXTRA_ATTACHMENT_ID, att.id)
        }
        startActivity(i)
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
