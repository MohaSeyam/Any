package com.securedb.kiosk.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

object AppSelfProtection {

    private val SU_PATHS = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/data/adb/magisk"
    )

    data class IntegrityReport(
        val passed: Boolean,
        val findings: List<String>
    )

    fun evaluateEnvironment(
        context: Context,
        enforceStrictReleaseChecks: Boolean = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0
    ): IntegrityReport {
        val findings = mutableListOf<String>()

        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            findings.add("تم رصد اتصال أداة تنقيح/تتبع خارجية (Debugger Attached)")
        }

        if (detectInjectedFrameworks()) {
            findings.add("تم رصد مكتبات حقن ذاكرة مشبوهة (Frida / Xposed)")
        }

        if (enforceStrictReleaseChecks && detectRootBinaries()) {
            findings.add("تم رصد مؤشرات كسر حماية النظام (Root / Magisk)")
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val pkgInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                )
                if (pkgInfo.signingInfo == null) {
                    findings.add("شهادة توقيع حزمة التطبيق APK مفقودة")
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                @Suppress("DEPRECATION")
                val pkgInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                if (pkgInfo.signingInfo == null) {
                    findings.add("شهادة توقيع حزمة التطبيق APK مفقودة")
                }
            }
        } catch (_: Exception) {
            findings.add("تعذر التحقق من شهادة توقيع حزمة التطبيق")
        }

        return IntegrityReport(findings.isEmpty(), findings)
    }

    private fun detectRootBinaries(): Boolean =
        SU_PATHS.any { File(it).exists() }

    private fun detectInjectedFrameworks(): Boolean {
        return try {
            BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val lower = line!!.lowercase()
                    if (lower.contains("frida") || lower.contains("xposed") || lower.contains("substrate")) {
                        return true
                    }
                }
                false
            }
        } catch (_: Exception) {
            false
        }
    }
}
