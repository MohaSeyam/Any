package com.securedb.kiosk.ui

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securedb.kiosk.databinding.ActivityDatabaseBrowserBinding
import com.securedb.kiosk.databinding.ItemCatalogRecordBinding
import com.securedb.kiosk.db.SecureReadOnlyDbEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DatabaseBrowserActivity : BaseSecureActivity() {

    override val requiresAuthenticatedSession: Boolean = true

    private lateinit var binding: ActivityDatabaseBrowserBinding
    private lateinit var adapter: RecordsAdapter
    private var searchJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!enforceActiveSessionOrRedirect()) return

        binding = ActivityDatabaseBrowserBinding.inflate(layoutInflater)
        setContentView(binding.root)

        adapter = RecordsAdapter { clickedRecord ->
            val intent = Intent(this, RecordDetailActivity::class.java).apply {
                putExtra(RecordDetailActivity.EXTRA_RECORD_ID, clickedRecord.id)
            }
            startActivity(intent)
        }

        binding.rvRecords.layoutManager = LinearLayoutManager(this)
        binding.rvRecords.adapter = adapter

        val user = secureApp.activeUsername ?: "User"
        val deviceId = secureApp.licenseManager.getDeviceId()
        binding.watermarkOverlay.setWatermarkInfo(user, deviceId)

        binding.btnLockNow.setOnClickListener {
            secureApp.terminateSession()
            navigateClearStack(LoginActivity::class.java)
        }

        binding.etSearchQuery.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                runQuery(s?.toString().orEmpty())
            }
        })

        loadStatsAndInitialData()
    }

    private fun loadStatsAndInitialData() {
        lifecycleScope.launch {
            try {
                val info = withContext(Dispatchers.IO) {
                    secureApp.dbEngine.getDatabaseInfo()
                }
                val sizeText = formatBytes(info.fileSizeBytes)
                val ftsLabel = if (info.ftsEnabled) "FTS5 نشط" else "قياسي"
                binding.tvDbStatsBar.text =
                    "${info.cipherVersion} • سجلات: ${info.totalRecords} • مرفقات: ${info.totalAttachments} • $sizeText • $ftsLabel"
                runQuery(binding.etSearchQuery.text?.toString().orEmpty())
            } catch (_: Exception) {
                secureApp.terminateSession()
                navigateClearStack(LoginActivity::class.java)
            }
        }
    }

    private fun runQuery(query: String) {
        searchJob?.cancel()
        searchJob = lifecycleScope.launch {
            try {
                val rows = withContext(Dispatchers.IO) {
                    secureApp.dbEngine.searchRecords(query = query, limit = 100, offset = 0)
                }
                adapter.submitList(rows)
            } catch (_: Exception) {
                enforceActiveSessionOrRedirect()
            }
        }
    }

    private fun formatBytes(bytes: Long): String {
        val mb = bytes / (1024.0 * 1024.0)
        val gb = mb / 1024.0
        return when {
            gb >= 1.0 -> String.format("%.2f GB", gb)
            mb >= 1.0 -> String.format("%.2f MB", mb)
            else -> "${bytes / 1024} KB"
        }
    }

    private class RecordsAdapter(
        private val onRecordClick: (SecureReadOnlyDbEngine.CatalogRecord) -> Unit
    ) : RecyclerView.Adapter<RecordsAdapter.Holder>() {

        private var items: List<SecureReadOnlyDbEngine.CatalogRecord> = emptyList()

        fun submitList(newItems: List<SecureReadOnlyDbEngine.CatalogRecord>) {
            items = newItems
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
            val b = ItemCatalogRecordBinding.inflate(
                LayoutInflater.from(parent.context),
                parent,
                false
            )
            return Holder(b)
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val item = items[position]
            holder.binding.tvRecordCode.text = item.code
            holder.binding.tvRecordClassification.text = item.classification
            holder.binding.tvRecordTitle.text = item.title
            holder.binding.tvRecordCategory.text = item.category
            holder.binding.tvRecordDetails.text = item.details

            if (item.attachmentCount > 0) {
                holder.binding.tvAttachmentBadge.visibility = View.VISIBLE
                holder.binding.tvAttachmentBadge.text = "📎 ${item.attachmentCount} مرفقات"
            } else {
                holder.binding.tvAttachmentBadge.visibility = View.GONE
            }

            holder.binding.root.setOnClickListener { onRecordClick(item) }
        }

        override fun getItemCount(): Int = items.size

        class Holder(val binding: ItemCatalogRecordBinding) : RecyclerView.ViewHolder(binding.root)
    }
}
