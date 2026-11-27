package com.securedb.kiosk.kiosk

import android.Manifest
import android.app.Activity
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.UserManager
import com.securedb.kiosk.ui.LauncherActivity

class KioskDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        KioskPolicyManager.applyKioskRestrictions(context, sealAdb = false)
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            KioskPolicyManager.applyKioskRestrictions(context, sealAdb = false)
        }
    }
}

object KioskPolicyManager {

    fun adminComponent(context: Context): ComponentName =
        ComponentName(context, KioskDeviceAdminReceiver::class.java)

    fun isDeviceOwner(context: Context): Boolean {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        return dpm.isDeviceOwnerApp(context.packageName)
    }

    fun applyKioskRestrictions(context: Context, sealAdb: Boolean) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        if (!dpm.isDeviceOwnerApp(context.packageName)) return

        val admin = adminComponent(context)

        // تعيين التطبيق كشاشة رئيسية دائمة للإقلاع التلقائي في أندرويد 10+
        val homeFilter = IntentFilter(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            addCategory(Intent.CATEGORY_DEFAULT)
        }
        dpm.addPersistentPreferredActivity(
            admin,
            homeFilter,
            ComponentName(context, LauncherActivity::class.java)
        )

        // منح صلاحية الكاميرا مسبقاً حتى لا يحجب وضع Lock Task نافذة طلب الصلاحية عند مسح QR
        dpm.setPermissionGrantState(
            admin,
            context.packageName,
            Manifest.permission.CAMERA,
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        )

        dpm.setLockTaskPackages(admin, arrayOf(context.packageName))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            dpm.setLockTaskFeatures(admin, DevicePolicyManager.LOCK_TASK_FEATURE_NONE)
        }

        dpm.addUserRestriction(admin, UserManager.DISALLOW_USB_FILE_TRANSFER)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_MOUNT_PHYSICAL_MEDIA)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_SAFE_BOOT)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_APPS_CONTROL)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_FACTORY_RESET)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_ADD_USER)
        dpm.addUserRestriction(admin, UserManager.DISALLOW_BLUETOOTH_SHARING)

        dpm.setBackupServiceEnabled(admin, false)

        if (sealAdb) {
            dpm.addUserRestriction(admin, UserManager.DISALLOW_DEBUGGING_FEATURES)
        }
    }

    fun syncDeviceClockIfDeviceOwner(context: Context, verifiedTimeMs: Long) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isDeviceOwner(context)) {
            try {
                val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                dpm.setTime(adminComponent(context), verifiedTimeMs)
            } catch (_: Exception) {
            }
        }
    }

    fun enterKioskLockTaskIfPermitted(activity: Activity) {
        val dpm = activity.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        if (dpm.isLockTaskPermitted(activity.packageName)) {
            try {
                activity.startLockTask()
            } catch (_: Exception) {
            }
        }
    }
}
