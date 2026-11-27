package com.securedb.kiosk.db

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import android.os.ParcelFileDescriptor
import com.securedb.kiosk.security.CryptoEngine
import com.securedb.kiosk.security.SecurityConfig
import net.zetetic.database.DatabaseErrorHandler
import net.zetetic.database.sqlcipher.SQLiteConnection
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteDatabaseHook
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import kotlin.math.min

class SecureReadOnlyDbEngine(private val context: Context) {

    data class CatalogRecord(
        val id: Long,
        val code: String,
        val category: String,
        val title: String,
        val details: String,
        val classification: String,
        val attachmentCount: Int
    )

    data class AttachmentMeta(
        val id: Long,
        val recordId: Long,
        val fileName: String,
        val mimeType: String,
        val sizeBytes: Long,
        val sha256Hex: String,
        val description: String,
        val thumbnailBytes: ByteArray?
    )

    data class DbInfo(
        val totalRecords: Long,
        val totalAttachments: Long,
        val fileSizeBytes: Long,
        val cipherVersion: String,
        val ftsEnabled: Boolean
    )

    @Volatile
    private var activeDb: SQLiteDatabase? = null

    private var activeSessionKeyBytes: ByteArray? = null

    /**
     * معالج أخطاء صامت يمنع DefaultDatabaseErrorHandler من حذف ملف قاعدة الـ 100GB عند أي خطأ فتح!
     */
    private val nonDeletingErrorHandler = DatabaseErrorHandler { /* Never delete read-only DB */ }

    /**
     * تهيئة حجم الصفحة المشفرة 16KB لملفات الـ 100GB والصور الضخمة فور تمرير المفتاح.
     */
    private val page16kHook = object : SQLiteDatabaseHook {
        override fun preKey(connection: SQLiteConnection) {}
        override fun postKey(connection: SQLiteConnection) {
            connection.execute("PRAGMA cipher_page_size = 16384;", null, null)
        }
    }

    init {
        System.loadLibrary("sqlcipher")
        purgeAnyResidualSwapFiles()
    }

    fun isOpen(): Boolean = activeDb?.isOpen == true

    @Synchronized
    fun openReadOnly(rawDek32Bytes: ByteArray) {
        var sqlcipherKeyBytes: ByteArray? = null
        try {
            require(rawDek32Bytes.size == 32) { "طول مفتاح فك تشفير قاعدة البيانات غير صالح" }
            closeSession()

            val dbFile = context.getDatabasePath(SecurityConfig.DATABASE_FILENAME)
            require(dbFile.exists() && dbFile.length() > 0L) {
                "ملف قاعدة البيانات المشفرة غير موجود في التخزين الداخلي المعزول!"
            }

            val hexChars = CryptoEngine.bytesToHex(rawDek32Bytes)
            sqlcipherKeyBytes = "x'$hexChars'".toByteArray(StandardCharsets.UTF_8)

            // محاولة الفتح بحجم صفحة 16KB المعتمد، مع دعم تلقائي لحجم 4KB القياسي إن أنشئت القاعدة بالإعداد الافتراضي
            val db = try {
                openWithHookAndVerify(dbFile, sqlcipherKeyBytes, page16kHook)
            } catch (_: Exception) {
                openWithHookAndVerify(dbFile, sqlcipherKeyBytes, null)
            }

            activeDb = db
            activeSessionKeyBytes = sqlcipherKeyBytes
            sqlcipherKeyBytes = null // نحتفظ بالمرجع في activeSessionKeyBytes ليُصفر عند closeSession()
        } finally {
            CryptoEngine.zeroize(rawDek32Bytes, sqlcipherKeyBytes)
        }
    }

    private fun openWithHookAndVerify(
        dbFile: File,
        keyBytes: ByteArray,
        hook: SQLiteDatabaseHook?
    ): SQLiteDatabase {
        val db = SQLiteDatabase.openDatabase(
            dbFile.absolutePath,
            keyBytes,
            null,
            SQLiteDatabase.OPEN_READONLY,
            nonDeletingErrorHandler,
            hook
        )
        try {
            db.rawQuery("PRAGMA query_only = ON;", null).use { it.moveToFirst() }
            db.rawQuery("PRAGMA temp_store = MEMORY;", null).use { it.moveToFirst() }
            db.rawQuery("PRAGMA cache_size = -32768;", null).use { it.moveToFirst() }
            db.rawQuery("SELECT count(*) FROM sqlite_master;", null).use { it.moveToFirst() }
            return db
        } catch (e: Exception) {
            try {
                db.close()
            } catch (_: Exception) {
            }
            throw e
        }
    }

    @Synchronized
    fun getDatabaseInfo(): DbInfo {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        val dbFile = context.getDatabasePath(SecurityConfig.DATABASE_FILENAME)

        var cipherVer = "SQLCipher 4"
        db.rawQuery("PRAGMA cipher_version;", null).use { c ->
            if (c.moveToFirst()) cipherVer = "SQLCipher ${c.getString(0)}"
        }

        var recordCount = 0L
        db.rawQuery("SELECT COUNT(*) FROM catalog_records;", null).use { c ->
            if (c.moveToFirst()) recordCount = c.getLong(0)
        }

        var attachmentCount = 0L
        if (hasTable(db, "record_attachments")) {
            db.rawQuery("SELECT COUNT(*) FROM record_attachments;", null).use { c ->
                if (c.moveToFirst()) attachmentCount = c.getLong(0)
            }
        }

        return DbInfo(
            totalRecords = recordCount,
            totalAttachments = attachmentCount,
            fileSizeBytes = dbFile.length(),
            cipherVersion = cipherVer,
            ftsEnabled = hasTable(db, "catalog_fts")
        )
    }

    @Synchronized
    fun searchRecords(
        query: String,
        categoryFilter: String? = null,
        limit: Int = 60,
        offset: Int = 0
    ): List<CatalogRecord> {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        val clean = query.trim()
        val cat = categoryFilter?.trim()?.takeIf { it.isNotEmpty() }

        val sql: String
        val args: Array<String>
        val ftsMatch = buildSafeFts5Query(clean)

        if (clean.isEmpty()) {
            if (cat == null) {
                sql = """
                    SELECT id, code, category, title, details, classification, attachment_count
                    FROM catalog_records
                    ORDER BY id ASC
                    LIMIT ? OFFSET ?;
                """.trimIndent()
                args = arrayOf(limit.toString(), offset.toString())
            } else {
                sql = """
                    SELECT id, code, category, title, details, classification, attachment_count
                    FROM catalog_records
                    WHERE category = ?
                    ORDER BY id ASC
                    LIMIT ? OFFSET ?;
                """.trimIndent()
                args = arrayOf(cat, limit.toString(), offset.toString())
            }
        } else if (ftsMatch != null && hasTable(db, "catalog_fts")) {
            if (cat == null) {
                sql = """
                    SELECT r.id, r.code, r.category, r.title, r.details, r.classification, r.attachment_count
                    FROM catalog_fts f
                    JOIN catalog_records r ON r.id = f.rowid
                    WHERE catalog_fts MATCH ?
                    ORDER BY r.id ASC
                    LIMIT ? OFFSET ?;
                """.trimIndent()
                args = arrayOf(ftsMatch, limit.toString(), offset.toString())
            } else {
                sql = """
                    SELECT r.id, r.code, r.category, r.title, r.details, r.classification, r.attachment_count
                    FROM catalog_fts f
                    JOIN catalog_records r ON r.id = f.rowid
                    WHERE catalog_fts MATCH ? AND r.category = ?
                    ORDER BY r.id ASC
                    LIMIT ? OFFSET ?;
                """.trimIndent()
                args = arrayOf(ftsMatch, cat, limit.toString(), offset.toString())
            }
        } else {
            val like = "%$clean%"
            sql = """
                SELECT id, code, category, title, details, classification, attachment_count
                FROM catalog_records
                WHERE (code LIKE ? OR title LIKE ? OR details LIKE ?)
                ${if (cat != null) "AND category = ?" else ""}
                ORDER BY id ASC
                LIMIT ? OFFSET ?;
            """.trimIndent()
            args = if (cat != null) {
                arrayOf(like, like, like, cat, limit.toString(), offset.toString())
            } else {
                arrayOf(like, like, like, limit.toString(), offset.toString())
            }
        }

        val results = mutableListOf<CatalogRecord>()
        db.rawQuery(sql, args).use { cursor ->
            while (cursor.moveToNext()) {
                results.add(
                    CatalogRecord(
                        id = cursor.getLong(0),
                        code = cursor.getString(1),
                        category = cursor.getString(2),
                        title = cursor.getString(3),
                        details = cursor.getString(4),
                        classification = cursor.getString(5),
                        attachmentCount = cursor.getInt(6)
                    )
                )
            }
        }
        return results
    }

    @Synchronized
    fun getRecordById(recordId: Long): CatalogRecord? {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        db.rawQuery(
            """
            SELECT id, code, category, title, details, classification, attachment_count
            FROM catalog_records WHERE id = ?;
            """.trimIndent(),
            arrayOf(recordId.toString())
        ).use { c ->
            if (!c.moveToFirst()) return null
            return CatalogRecord(
                id = c.getLong(0),
                code = c.getString(1),
                category = c.getString(2),
                title = c.getString(3),
                details = c.getString(4),
                classification = c.getString(5),
                attachmentCount = c.getInt(6)
            )
        }
    }

    @Synchronized
    fun getAttachmentsForRecord(recordId: Long): List<AttachmentMeta> {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        if (!hasTable(db, "record_attachments")) return emptyList()

        val list = mutableListOf<AttachmentMeta>()
        db.rawQuery(
            """
            SELECT id, record_id, file_name, mime_type, size_bytes, sha256_hex, description, thumbnail_blob
            FROM record_attachments
            WHERE record_id = ?
            ORDER BY id ASC;
            """.trimIndent(),
            arrayOf(recordId.toString())
        ).use { c ->
            while (c.moveToNext()) {
                list.add(
                    AttachmentMeta(
                        id = c.getLong(0),
                        recordId = c.getLong(1),
                        fileName = c.getString(2),
                        mimeType = c.getString(3),
                        sizeBytes = c.getLong(4),
                        sha256Hex = c.getString(5),
                        description = c.getString(6),
                        thumbnailBytes = if (c.isNull(7)) null else c.getBlob(7)
                    )
                )
            }
        }
        return list
    }

    @Synchronized
    fun getAttachmentMetaById(attachmentId: Long): AttachmentMeta? {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        db.rawQuery(
            """
            SELECT id, record_id, file_name, mime_type, size_bytes, sha256_hex, description
            FROM record_attachments WHERE id = ?;
            """.trimIndent(),
            arrayOf(attachmentId.toString())
        ).use { c ->
            if (!c.moveToFirst()) return null
            return AttachmentMeta(
                id = c.getLong(0),
                recordId = c.getLong(1),
                fileName = c.getString(2),
                mimeType = c.getString(3),
                sizeBytes = c.getLong(4),
                sha256Hex = c.getString(5),
                description = c.getString(6),
                thumbnailBytes = null
            )
        }
    }

    @Synchronized
    fun readAttachmentToMemoryVerified(
        attachmentId: Long,
        expectedSha256Hex: String,
        maxAllowedBytes: Int = 40 * 1024 * 1024
    ): ByteArray {
        val totalLen = queryBlobLength(attachmentId)
        require(totalLen in 1..maxAllowedBytes.toLong()) {
            "حجم المرفق ($totalLen بايت) خارج النطاق المسموح للعرض المباشر بالذاكرة"
        }

        val out = ByteArray(totalLen.toInt())
        var writePos = 0
        try {
            streamBlobChunksVerified(attachmentId, totalLen, expectedSha256Hex) { chunk ->
                try {
                    System.arraycopy(chunk, 0, out, writePos, chunk.size)
                    writePos += chunk.size
                } finally {
                    CryptoEngine.zeroize(chunk)
                }
            }
            return out
        } catch (t: Throwable) {
            CryptoEngine.zeroize(out)
            throw t
        }
    }

    @Synchronized
    fun openVerifiedUnlinkedPdfDescriptor(
        attachmentId: Long,
        expectedSha256Hex: String
    ): ParcelFileDescriptor {
        val totalLen = queryBlobLength(attachmentId)
        require(totalLen > 0L) { "ملف PDF المرفق فارغ" }

        val swapDir = File(context.noBackupFilesDir, "volatile_swap").apply { mkdirs() }
        val transientFile = File(swapDir, "mem_${System.nanoTime()}.bin")

        try {
            FileOutputStream(transientFile).use { fos ->
                streamBlobChunksVerified(attachmentId, totalLen, expectedSha256Hex) { chunk ->
                    try {
                        fos.write(chunk)
                    } finally {
                        CryptoEngine.zeroize(chunk)
                    }
                }
            }
            val pfd = ParcelFileDescriptor.open(transientFile, ParcelFileDescriptor.MODE_READ_ONLY)
            transientFile.delete()
            return pfd
        } catch (e: Exception) {
            transientFile.delete()
            throw e
        }
    }

    private fun queryBlobLength(attachmentId: Long): Long {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        db.rawQuery(
            "SELECT LENGTH(payload_blob) FROM attachment_blobs WHERE attachment_id = ?;",
            arrayOf(attachmentId.toString())
        ).use { c ->
            require(c.moveToFirst() && !c.isNull(0)) { "بيانات المرفق غير موجودة في قاعدة البيانات" }
            return c.getLong(0)
        }
    }

    private inline fun streamBlobChunksVerified(
        attachmentId: Long,
        totalBytes: Long,
        expectedSha256Hex: String,
        onChunk: (ByteArray) -> Unit
    ) {
        val db = requireNotNull(activeDb) { "جلسة قاعدة البيانات مغلقة" }
        val digest = MessageDigest.getInstance("SHA-256")
        val chunkLimit = SecurityConfig.BLOB_STREAM_CHUNK_BYTES.toLong()
        var offsetZeroBased = 0L

        while (offsetZeroBased < totalBytes) {
            val sqlOneBasedStart = offsetZeroBased + 1L
            val readLen = min(chunkLimit, totalBytes - offsetZeroBased)

            val chunk: ByteArray = db.rawQuery(
                "SELECT SUBSTR(payload_blob, ?, ?) FROM attachment_blobs WHERE attachment_id = ?;",
                arrayOf(sqlOneBasedStart.toString(), readLen.toString(), attachmentId.toString())
            ).use { c ->
                require(c.moveToFirst() && !c.isNull(0)) { "انقطاع أثناء قراءة شرائح المرفق المشفر" }
                c.getBlob(0)
            }

            require(chunk.isNotEmpty() && chunk.size <= readLen.toInt()) {
                "حجم شريحة البيانات المقروءة غير متسق"
            }

            digest.update(chunk)
            val step = chunk.size.toLong()
            onChunk(chunk)
            offsetZeroBased += step
        }

        val actualSha256 = CryptoEngine.bytesToHex(digest.digest())
        if (!actualSha256.equals(expectedSha256Hex, ignoreCase = true)) {
            throw SecurityException("فشل التحقق من سلامة المرفق (عدم تطابق البصمة التشفيرية SHA-256)!")
        }
    }

    @Synchronized
    fun closeSession() {
        try {
            activeDb?.close()
        } catch (_: Exception) {
        } finally {
            activeDb = null
            CryptoEngine.zeroize(activeSessionKeyBytes)
            activeSessionKeyBytes = null
            purgeAnyResidualSwapFiles()
        }
    }

    private fun purgeAnyResidualSwapFiles() {
        val swapDir = File(context.noBackupFilesDir, "volatile_swap")
        if (swapDir.exists()) {
            swapDir.listFiles()?.forEach { file ->
                try {
                    file.delete()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun hasTable(db: SQLiteDatabase, tableName: String): Boolean {
        db.rawQuery(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ? LIMIT 1;",
            arrayOf(tableName)
        ).use { return it.moveToFirst() }
    }

    companion object {
        private val UNICODE_WORD_REGEX = Regex("[\\p{L}\\p{M}\\p{N}_]+")

        /**
         * يستخرج الكلمات المتوافقة مع محلل unicode61 في FTS5 (عربي/إنجليزي/أرقام) ويتجاهل الرموز الخاصة بأمان.
         */
        fun buildSafeFts5Query(rawInput: String): String? {
            val tokens = UNICODE_WORD_REGEX.findAll(rawInput)
                .map { it.value }
                .filter { it.isNotEmpty() }
                .toList()
            if (tokens.isEmpty()) return null
            return tokens.joinToString(" AND ") { "\"$it\"*" }
        }
    }

    @Synchronized
    fun generateLabSampleEncryptedDatabase(sampleRowCount: Int = 250): ByteArray {
        val dbFile: File = context.getDatabasePath(SecurityConfig.DATABASE_FILENAME)
        dbFile.parentFile?.mkdirs()
        if (dbFile.exists()) dbFile.delete()
        File("${dbFile.absolutePath}-journal").delete()
        File("${dbFile.absolutePath}-wal").delete()
        File("${dbFile.absolutePath}-shm").delete()

        val rawDek = CryptoEngine.randomBytes(32)
        val dekHex = CryptoEngine.bytesToHex(rawDek)
        val sqlcipherKeyBytes = "x'$dekHex'".toByteArray(StandardCharsets.UTF_8)

        try {
            val db = SQLiteDatabase.openDatabase(
                dbFile.absolutePath,
                sqlcipherKeyBytes,
                null,
                SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY,
                nonDeletingErrorHandler,
                page16kHook
            )
            try {
                db.rawQuery("PRAGMA journal_mode = DELETE;", null).use { it.moveToFirst() }

                db.execSQL(
                    """
                    CREATE TABLE catalog_records (
                        id INTEGER PRIMARY KEY,
                        code TEXT NOT NULL UNIQUE,
                        category TEXT NOT NULL,
                        title TEXT NOT NULL,
                        details TEXT NOT NULL,
                        classification TEXT NOT NULL,
                        attachment_count INTEGER NOT NULL DEFAULT 0
                    );
                    """.trimIndent()
                )
                db.execSQL("CREATE INDEX idx_catalog_code ON catalog_records(code);")
                db.execSQL("CREATE INDEX idx_catalog_category ON catalog_records(category);")

                db.execSQL(
                    """
                    CREATE VIRTUAL TABLE catalog_fts USING fts5(
                        code,
                        category,
                        title,
                        details,
                        content='catalog_records',
                        content_rowid='id',
                        tokenize='unicode61'
                    );
                    """.trimIndent()
                )

                db.execSQL(
                    """
                    CREATE TABLE record_attachments (
                        id INTEGER PRIMARY KEY,
                        record_id INTEGER NOT NULL,
                        file_name TEXT NOT NULL,
                        mime_type TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        sha256_hex TEXT NOT NULL,
                        description TEXT NOT NULL,
                        thumbnail_blob BLOB,
                        FOREIGN KEY(record_id) REFERENCES catalog_records(id)
                    );
                    """.trimIndent()
                )
                db.execSQL("CREATE INDEX idx_att_record_id ON record_attachments(record_id);")

                db.execSQL(
                    """
                    CREATE TABLE attachment_blobs (
                        attachment_id INTEGER PRIMARY KEY,
                        payload_blob BLOB NOT NULL,
                        FOREIGN KEY(attachment_id) REFERENCES record_attachments(id)
                    );
                    """.trimIndent()
                )

                val schematicPngAndThumb = generateSampleSchematicPngAndThumb("SEC-REF-00001")
                val largeBmpOver2Mb = generateLargeBmpAttachmentOver2Mb(width = 1024, height = 900)
                val samplePdfBytes = generateTwoPageSamplePdf()

                val categories = listOf(
                    "المخططات الهندسية المصورة",
                    "المواصفات الفنية والمرفقات",
                    "دليل المعدات الميدانية",
                    "الوثائق المرجعية المعتمدة",
                    "جداول الفحص والمعايرة"
                )
                val classifications = listOf("سري للغاية", "مقيد - داخلي", "للقراءة الميدانية فقط")

                db.beginTransaction()
                val recStmt = db.compileStatement(
                    """
                    INSERT INTO catalog_records (id, code, category, title, details, classification, attachment_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """.trimIndent()
                )
                val attMetaStmt = db.compileStatement(
                    """
                    INSERT INTO record_attachments (id, record_id, file_name, mime_type, size_bytes, sha256_hex, description, thumbnail_blob)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """.trimIndent()
                )
                val attBlobStmt = db.compileStatement(
                    "INSERT INTO attachment_blobs (attachment_id, payload_blob) VALUES (?, ?);"
                )

                try {
                    var nextAttId = 1L
                    for (i in 1..sampleRowCount) {
                        val cat = categories[(i - 1) % categories.size]
                        val cls = classifications[(i - 1) % classifications.size]
                        val code = String.format(Locale.US, "SEC-REF-%05d", i)
                        val hasRichAttachments = (i <= 10)
                        val attCount = when {
                            i == 1 -> 3
                            hasRichAttachments -> 2
                            else -> 0
                        }

                        val title = if (i == 1) {
                            "ملف مرجعي شامل ومخططات هندسية وصورة 2.7MB ومستند PDF ($code)"
                        } else {
                            "ملف مرجعي مشفر رقم $i — $cat"
                        }
                        val details = buildString {
                            append("سجل مرجعي ومخططات هندسية محمية بتشفير SQLCipher 4 (AES-256 + HMAC-SHA512) ومفهرسة عبر FTS5. ")
                            append("رقم المرجع: $code | التصنيف: $cls. ")
                            if (attCount > 0) {
                                append("يشتمل هذا السجل على $attCount مرفقات مشفرة (صور ومستندات) تُعرض داخل الذاكرة دون ملفات مؤقتة.")
                            }
                        }

                        recStmt.clearBindings()
                        recStmt.bindLong(1, i.toLong())
                        recStmt.bindString(2, code)
                        recStmt.bindString(3, cat)
                        recStmt.bindString(4, title)
                        recStmt.bindString(5, details)
                        recStmt.bindString(6, cls)
                        recStmt.bindLong(7, attCount.toLong())
                        recStmt.executeInsert()

                        if (hasRichAttachments) {
                            val (pngBytes, thumbBytes) = schematicPngAndThumb
                            insertAttachmentHelper(
                                attMetaStmt = attMetaStmt,
                                attBlobStmt = attBlobStmt,
                                attId = nextAttId++,
                                recordId = i.toLong(),
                                fileName = "diagram_$code.png",
                                mimeType = "image/png",
                                description = "مخطط تفصيلي عالي الوضوح قابل للتكبير داخل العارض الآمن",
                                payload = pngBytes,
                                thumbnail = thumbBytes
                            )

                            if (i == 1) {
                                insertAttachmentHelper(
                                    attMetaStmt = attMetaStmt,
                                    attBlobStmt = attBlobStmt,
                                    attId = nextAttId++,
                                    recordId = 1L,
                                    fileName = "highres_scan_2_7mb.bmp",
                                    mimeType = "image/bmp",
                                    description = "صورة فحص عالية الدقة (2.76 MB) لإثبات نجاح البث المجزأ فوق حد 2MB CursorWindow",
                                    payload = largeBmpOver2Mb,
                                    thumbnail = thumbBytes
                                )
                            }

                            if (i % 2 == 1) {
                                insertAttachmentHelper(
                                    attMetaStmt = attMetaStmt,
                                    attBlobStmt = attBlobStmt,
                                    attId = nextAttId++,
                                    recordId = i.toLong(),
                                    fileName = "manual_$code.pdf",
                                    mimeType = "application/pdf",
                                    description = "وثيقة فنية رسمية متعددة الصفحات بصيغة PDF (صفحتان)",
                                    payload = samplePdfBytes,
                                    thumbnail = null
                                )
                            } else {
                                val reportBytes = """
                                    وثيقة مواصفات فنية داخلية — $code
                                    =======================================
                                    التصنيف الأمني: $cls
                                    حالة الاتصال: معزول عن الشبكة نهائياً (Air-Gapped)
                                    وضع القاعدة: للقراءة فقط (OPEN_READONLY + query_only)
                                    
                                    بنود الفحص المعتمدة:
                                    1. التحقق من البصمة التشفيرية SHA-256 للمرفق أثناء البث المجزأ.
                                    2. منع أخذ لقطات الشاشة (FLAG_SECURE) وتطبيق العلامة المائية باسم المستخدم.
                                    3. تصفير البيانات من الذاكرة العشوائية فور إغلاق نافذة المعاينة.
                                """.trimIndent().toByteArray(StandardCharsets.UTF_8)

                                insertAttachmentHelper(
                                    attMetaStmt = attMetaStmt,
                                    attBlobStmt = attBlobStmt,
                                    attId = nextAttId++,
                                    recordId = i.toLong(),
                                    fileName = "tech_spec_$code.txt",
                                    mimeType = "text/plain",
                                    description = "تقرير المواصفات الفنية التفصيلي (نص مشفر)",
                                    payload = reportBytes,
                                    thumbnail = null
                                )
                            }
                        }
                    }

                    db.execSQL("INSERT INTO catalog_fts(catalog_fts) VALUES('rebuild');")
                    db.setTransactionSuccessful()
                } finally {
                    recStmt.close()
                    attMetaStmt.close()
                    attBlobStmt.close()
                    db.endTransaction()
                }
            } finally {
                db.close()
            }
            return rawDek
        } catch (e: Exception) {
            CryptoEngine.zeroize(rawDek)
            throw e
        } finally {
            CryptoEngine.zeroize(sqlcipherKeyBytes)
        }
    }

    private fun insertAttachmentHelper(
        attMetaStmt: net.zetetic.database.sqlcipher.SQLiteStatement,
        attBlobStmt: net.zetetic.database.sqlcipher.SQLiteStatement,
        attId: Long,
        recordId: Long,
        fileName: String,
        mimeType: String,
        description: String,
        payload: ByteArray,
        thumbnail: ByteArray?
    ) {
        val sha256 = CryptoEngine.sha256Hex(payload)
        attMetaStmt.clearBindings()
        attMetaStmt.bindLong(1, attId)
        attMetaStmt.bindLong(2, recordId)
        attMetaStmt.bindString(3, fileName)
        attMetaStmt.bindString(4, mimeType)
        attMetaStmt.bindLong(5, payload.size.toLong())
        attMetaStmt.bindString(6, sha256)
        attMetaStmt.bindString(7, description)
        if (thumbnail != null) {
            attMetaStmt.bindBlob(8, thumbnail)
        } else {
            attMetaStmt.bindNull(8)
        }
        attMetaStmt.executeInsert()

        attBlobStmt.clearBindings()
        attBlobStmt.bindLong(1, attId)
        attBlobStmt.bindBlob(2, payload)
        attBlobStmt.executeInsert()
    }

    private fun generateSampleSchematicPngAndThumb(code: String): Pair<ByteArray, ByteArray> {
        val bmp = Bitmap.createBitmap(1000, 700, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        canvas.drawColor(Color.rgb(15, 23, 42))

        val gridPaint = Paint().apply {
            color = Color.rgb(30, 58, 138)
            strokeWidth = 2f
        }
        for (x in 0..1000 step 50) canvas.drawLine(x.toFloat(), 0f, x.toFloat(), 700f, gridPaint)
        for (y in 0..700 step 50) canvas.drawLine(0f, y.toFloat(), 1000f, y.toFloat(), gridPaint)

        val boxPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(56, 189, 248)
            style = Paint.Style.STROKE
            strokeWidth = 5f
        }
        canvas.drawRect(80f, 90f, 920f, 610f, boxPaint)
        canvas.drawCircle(500f, 360f, 150f, boxPaint)
        canvas.drawLine(220f, 360f, 780f, 360f, boxPaint)
        canvas.drawLine(500f, 160f, 500f, 560f, boxPaint)

        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = 34f
            isFakeBoldText = true
        }
        canvas.drawText("مخطط هندسي مشفر داخل قاعدة البيانات — $code", 130f, 155f, textPaint)
        textPaint.textSize = 24f
        textPaint.color = Color.rgb(250, 204, 21)
        canvas.drawText("SQLCipher AES-256 + SHA-256 Verified In-Memory Image", 190f, 580f, textPaint)

        val fullOut = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.PNG, 100, fullOut)

        val thumbBmp = Bitmap.createScaledBitmap(bmp, 160, 112, true)
        val thumbOut = ByteArrayOutputStream()
        thumbBmp.compress(Bitmap.CompressFormat.JPEG, 75, thumbOut)

        thumbBmp.recycle()
        bmp.recycle()
        return fullOut.toByteArray() to thumbOut.toByteArray()
    }

    private fun generateLargeBmpAttachmentOver2Mb(width: Int, height: Int): ByteArray {
        val rowBytes = width * 3
        val pixelDataSize = rowBytes * height
        val fileSize = 54 + pixelDataSize
        val buf = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)

        buf.put('B'.code.toByte())
        buf.put('M'.code.toByte())
        buf.putInt(fileSize)
        buf.putShort(0)
        buf.putShort(0)
        buf.putInt(54)

        buf.putInt(40)
        buf.putInt(width)
        buf.putInt(height)
        buf.putShort(1)
        buf.putShort(24)
        buf.putInt(0)
        buf.putInt(pixelDataSize)
        buf.putInt(2835)
        buf.putInt(2835)
        buf.putInt(0)
        buf.putInt(0)

        val row = ByteArray(rowBytes)
        for (y in 0 until height) {
            val g = ((y * 255) / height).toByte()
            var idx = 0
            for (x in 0 until width) {
                val b = ((x * 255) / width).toByte()
                val r = (((x xor y) and 0xFF)).toByte()
                row[idx++] = b
                row[idx++] = g
                row[idx++] = r
            }
            buf.put(row)
        }
        return buf.array()
    }

    private fun generateTwoPageSamplePdf(): ByteArray {
        val pdf = PdfDocument()
        try {
            for (pageNum in 1..2) {
                val pageInfo = PdfDocument.PageInfo.Builder(595, 842, pageNum).create()
                val page = pdf.startPage(pageInfo)
                val c = page.canvas
                c.drawColor(Color.WHITE)

                val border = Paint().apply {
                    color = Color.rgb(30, 58, 138)
                    style = Paint.Style.STROKE
                    strokeWidth = 4f
                }
                c.drawRect(36f, 36f, 559f, 806f, border)

                val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(15, 23, 42)
                    textSize = 22f
                    isFakeBoldText = true
                }
                c.drawText("وثيقة مرجعية مشفرة (PDF) — الصفحة $pageNum من 2", 95f, 95f, titlePaint)

                val bodyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(51, 65, 85)
                    textSize = 14f
                }
                c.drawText("• يتم استخراج وعرض هذا الملف مباشرة من داخل SQLCipher دون تصدير خارجي.", 65f, 150f, bodyPaint)
                c.drawText("• تم التحقق من بصمة SHA-256 الكاملة للملف قبل عرض الصفحة.", 65f, 180f, bodyPaint)
                c.drawText("• وضع القاعدة: OPEN_READONLY (قراءة فقط — الجهاز معزول عن الإنترنت).", 65f, 210f, bodyPaint)

                val diagramPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = if (pageNum == 1) Color.rgb(15, 118, 110) else Color.rgb(180, 83, 9)
                    style = Paint.Style.STROKE
                    strokeWidth = 3f
                }
                c.drawRect(80f, 260f, 515f, 520f, diagramPaint)
                c.drawCircle(297f, 390f, 85f, diagramPaint)

                pdf.finishPage(page)
            }
            val out = ByteArrayOutputStream()
            pdf.writeTo(out)
            return out.toByteArray()
        } finally {
            pdf.close()
        }
    }
}
