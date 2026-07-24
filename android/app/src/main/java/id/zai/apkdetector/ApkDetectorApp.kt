package id.zai.apkdetector

import android.app.Application
import id.zai.apkdetector.data.HistoryDatabase
import id.zai.apkdetector.data.Repository

/**
 * Application entry point. Initializes Room DB + Repository singletons.
 *
 * Deliberately minimal — no analytics, no crash reporting, no remote config.
 */
class ApkDetectorApp : Application() {
    val database by lazy { HistoryDatabase.getInstance(this) }
    val repository by lazy { Repository(database.scanDao()) }

    companion object {
        private lateinit var instance: ApkDetectorApp
        fun get(): ApkDetectorApp = instance
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }
}
