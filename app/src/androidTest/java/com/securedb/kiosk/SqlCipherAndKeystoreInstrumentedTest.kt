package com.securedb.kiosk

import android.graphics.pdf.PdfRenderer
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securedb.kiosk.db.SecureReadOnlyDbEngine
import com.securedb.kiosk.security.LockoutAndTimeGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * اختبارات تكاملية على بيئة أندرويد الفعلية (Instrumented Tests):
 * 1. اختبار إنشاء قاعدة البيانات المشفرة بـ SQLCipher مع الصور (>2.7MB) والـ PDF وفهرس FTS5.
 * 2. إثبات رفض أي تعديل أو حذف في وضع القراءة فقط (OPEN_READONLY).
 * 3. إثبات نجاح البث المجزأ لصورة أكبر من 2MB دون انهيار CursorWindow مع تطابق SHA-256.
 * 4. إثبات فتح ملف PDF عبر الواصف محذوف الرابط (Zero files in volatile_swap).
 * 5. إثبات فشل هجوم استرجاع نسخة قديمة من ملف عداد المحاولات (Hardware Keystore Anti-Rollback).
 */
@RunWith(AndroidJUnit4::class)
class SqlCipherAndKeystoreInstrumentedTest {

    @Test
    fun sqlCipherReadOnly_streamsOver2MbImageAndUnlinkedPdfWithZeroDiskResidue() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val engine = SecureReadOnlyDbEngine(context)

        val rawDek = engine.generateLabSampleEncryptedDatabase(sampleRowCount = 25)
        engine.openReadOnly(rawDek)

        try {
            val info = engine.getDatabaseInfo()
            assertEquals(25L, info.totalRecords)
            assertTrue(info.ftsEnabled)
            assertTrue(info.totalAttachments >= 20L)

            // اختبار بحث FTS5 باللغة العربية
            val ftsHits = engine.searchRecords("المخططات")
            assertTrue(ftsHits.isNotEmpty())

            // إثبات رفض أي كتابة أو حذف في وضع القراءة فقط OPEN_READONLY
            val rawDbField = SecureReadOnlyDbEngine::class.java.getDeclaredField("activeDb").apply {
                isAccessible = true
            }
            val sqlDb = rawDbField.get(engine) as net.zetetic.database.sqlcipher.SQLiteDatabase
            try {
                sqlDb.execSQL("DELETE FROM catalog_records WHERE id = 1;")
                fail("يجب أن يرفض محرك القراءة فقط أي عملية تعديل أو حذف!")
            } catch (_: Exception) {
                // متوقع: SQLiteReadOnlyDatabaseException
            }

            // السجل الأول يحتوي على صورة > 2.7MB وملف PDF من صفحتين
            val attachments = engine.getAttachmentsForRecord(1L)
            assertEquals(3, attachments.size)

            val largeBmpMeta = attachments.first { it.mimeType == "image/bmp" }
            assertTrue("يجب أن يتجاوز حجم الصورة 2.5MB لاختبار حد CursorWindow", largeBmpMeta.sizeBytes > 2_500_000L)

            val streamedBytes = engine.readAttachmentToMemoryVerified(
                attachmentId = largeBmpMeta.id,
                expectedSha256Hex = largeBmpMeta.sha256Hex
            )
            assertEquals(largeBmpMeta.sizeBytes.toInt(), streamedBytes.size)

            // اختبار فتح PDF محذوف الرابط والتأكد من خلو مجلد volatile_swap تماماً على القرص
            val pdfMeta = attachments.first { it.mimeType == "application/pdf" }
            engine.openVerifiedUnlinkedPdfDescriptor(pdfMeta.id, pdfMeta.sha256Hex).use { pfd ->
                val swapDir = File(context.noBackupFilesDir, "volatile_swap")
                val filesOnDisk = swapDir.listFiles()?.size ?: 0
                assertEquals("يجب ألا يبقى أي ملف مرئي على القرص أثناء فتح PDF", 0, filesOnDisk)

                PdfRenderer(pfd).use { renderer ->
                    assertEquals(2, renderer.pageCount)
                }
            }
        } finally {
            engine.closeSession()
        }
    }

    @Test
    fun hardwareKeystoreAntiRollback_blocksRestoringOldCounterBackup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val guard = LockoutAndTimeGuard(context)
        guard.initializeOnActivation(System.currentTimeMillis())

        val counterFile = File(context.noBackupFilesDir, "failure_counter.sec")
        val attackerBackupAtZero = counterFile.readBytes()

        // استنفاد الـ 10 محاولات -> يدمر مفتاح ACTIVE_COUNTER_AES_ALIAS داخل عتاد Keystore
        for (i in 1..10) {
            guard.recordFailedLoginAttempt()
        }
        assertTrue(guard.inspectAndRefreshLockout().permanentlyLocked)

        // محاولة المهاجم حذف ملف القفل النهائي وإرجاع النسخة الاحتياطية القديمة لملف العداد (= 0)
        File(context.noBackupFilesDir, "permanent_lock.sec").delete()
        counterFile.writeBytes(attackerBackupAtZero)

        // يجب أن يفشل فك تشفير النسخة المسترجعة لأن المفتاح العتادي قد دُمّر، ويبقى التطبيق مغلقاً نهائياً!
        val afterRollbackAttempt = guard.inspectAndRefreshLockout()
        assertTrue("يجب أن تفشل محاولة استرجاع ملف العداد القديم", afterRollbackAttempt.permanentlyLocked)
    }
}
