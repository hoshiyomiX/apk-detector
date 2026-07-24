package id.zai.apkdetector.data

import androidx.room.Database
import androidx.room.Entity
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import android.content.Context

@Entity(tableName = "scans", primaryKeys = ["createdAt"])
data class ScanEntity(
    val apkLabel: String,
    val apkPath: String,
    val markdown: String,
    val createdAt: Long,
)

@Dao
interface ScanDao {
    @Query("SELECT * FROM scans ORDER BY createdAt DESC")
    suspend fun getAll(): List<ScanEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: ScanEntity)

    @Query("DELETE FROM scans")
    suspend fun deleteAll()
}

@Database(entities = [ScanEntity::class], version = 1, exportSchema = false)
abstract class HistoryDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao

    companion object {
        @Volatile
        private var INSTANCE: HistoryDatabase? = null

        fun getInstance(context: Context): HistoryDatabase {
            return INSTANCE ?: synchronized(this) {
                val db = Room.databaseBuilder(
                    context.applicationContext,
                    HistoryDatabase::class.java,
                    "apk_detector_history.db",
                ).build()
                INSTANCE = db
                db
            }
        }
    }
}
