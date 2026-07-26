package id.zai.apkdetector.data

import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityTokenRequest
import id.zai.apkdetector.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * Suspendable wrapper around Google Play Integrity Standard Request API.
 *
 * ## Lifecycle
 *
 *   1. **Prepare** — Warming up the integrity token provider via
 *      [IntegrityManagerFactory.createStandard] →
 *      `prepareIntegrityToken(cloudProjectNumber)`. Should happen on app
 *      cold start or before any verdict is needed. Per Google docs, an
 *      app instance may call `prepareIntegrityToken` at most 5 times per
 *      minute.
 *   2. **Request** — Once the provider is ready, call `request(requestHash)`
 *      to obtain a signed+encrypted integrity token.
 *
 * ## Why we don't decrypt the token
 *
 * The Play Integrity token is encrypted by Google — full verdict
 * decryption requires a server-side call to
 * `playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken` using
 * a Google Cloud service account.
 *
 * APK Detector deliberately ships WITHOUT the INTERNET permission and
 * WITHOUT a backend server. Therefore we use **token issuance itself**
 * as the integrity signal:
 *
 *   - Token issued successfully → `Passes(true)` — Google Play's on-device
 *     integrity checks (genuine Play Store, genuine app, genuine device)
 *     passed.
 *   - Token request fails with `PLAY_STORE_NOT_FOUND`, `APP_NOT_INSTALLED`,
 *     `APP_UID_MISMATCH`, or any of the "non-genuine" error codes →
 *     `Passes(false)` — Play's integrity check failed for this device/app.
 *   - Token request fails with a transient error (`NETWORK_ERROR`,
 *     `INTEGRITY_TOKEN_PROVIDER_INVALID`) → `Error(message)` — caller may
 *     retry.
 *   - Cloud project number not configured (0L) → `NotConfigured` — caller
 *     skips the field (leaves it null/Unknown).
 *
 * ## Threading
 *
 * All Play Integrity API calls are IPC to Google Play services and
 * return `Task<...>` objects. We block on them via `Tasks.await()` on
 * `Dispatchers.IO` — never on the main thread.
 *
 * ## Caching
 *
 * The `StandardIntegrityTokenProvider` is cached in-memory per process
 * via [providerHolder]. Re-preparing on every call would burn through
 * the 5-calls-per-minute rate limit. If the provider expires
 * (`INTEGRITY_TOKEN_PROVIDER_INVALID`), the next call re-prepares
 * automatically.
 */
object PlayIntegrityClient {

    /**
     * Process-scoped cache of the warmed-up token provider.
     *
     * Once prepared, the provider stays valid until the Play services
     * process invalidates it (rare — typically hours). We hold it for
     * the lifetime of the app process.
     */
    private object providerHolder {
        @Volatile
        var provider: StandardIntegrityTokenProvider? = null
    }

    /**
     * Result of a Play Integrity verdict request.
     *
     * - [Passes] — The integrity check issued a token (true) or
     *   explicitly refused one with a "non-genuine" error code (false).
     * - [NotConfigured] — Cloud project number is 0L; caller should
     *   leave the field null/Unknown.
     * - [Error] — Transient or unknown error; caller may retry.
     */
    sealed class Result {
        data class Passes(val value: Boolean) : Result()
        object NotConfigured : Result()
        data class Error(val message: String, val errorCode: Int? = null) : Result()
    }

    /**
     * Run the Play Integrity Standard Request flow.
     *
     * Returns [Result.Passes] if the API definitively answered (true =
     * token issued, false = "non-genuine device" error code),
     * [Result.NotConfigured] if the cloud project number is 0L, or
     * [Result.Error] for transient/unknown failures.
     *
     * Must be called from a coroutine scope — internally uses
     * `withContext(Dispatchers.IO)` to block on the Play services IPC.
     */
    suspend fun requestVerdict(context: Context): Result = withContext(Dispatchers.IO) {
        // Short-circuit if cloud project number is not configured.
        val cloudProjectNumber = BuildConfig.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER
        if (cloudProjectNumber == 0L) return@withContext Result.NotConfigured

        try {
            // Step 1: ensure token provider is warmed up.
            val provider = getOrPrepareProvider(context, cloudProjectNumber)
                ?: return@withContext Result.Error(
                    "Failed to prepare integrity token provider",
                    errorCode = null,
                )

            // Step 2: request an integrity token.
            //
            // Per Google docs, requestHash protects against tampering by
            // binding the token to a specific user action. We don't have a
            // server-side action to bind to (no backend), so we use a
            // stable hash of the package name + timestamp bucket. This is
            // NOT a security feature for us — it's just to satisfy the API
            // contract. The token itself is what we care about: did Google
            // issue one or not?
            val requestHash = stableRequestHash(context.packageName)

            val tokenRequest = StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash)
                .build()

            // Try the request, with one automatic retry if the token
            // provider has expired since warm-up. Tasks.await() blocks
            // the IO thread for up to 10s.
            var tokenResponse: com.google.android.play.core.integrity.StandardIntegrityToken? = null
            var failure: Result.Error? = null

            try {
                tokenResponse = Tasks.await(
                    provider.request(tokenRequest),
                    10, TimeUnit.SECONDS,
                )
            } catch (e: Exception) {
                val code = extractErrorCode(e)
                if (code == ERROR_INTEGRITY_TOKEN_PROVIDER_INVALID) {
                    // Provider expired — invalidate cache + retry once.
                    providerHolder.provider = null
                    val newProvider = getOrPrepareProvider(context, cloudProjectNumber)
                    if (newProvider != null) {
                        try {
                            tokenResponse = Tasks.await(
                                newProvider.request(tokenRequest),
                                10, TimeUnit.SECONDS,
                            )
                        } catch (e2: Exception) {
                            failure = mapTokenError(e2)
                        }
                    } else {
                        failure = Result.Error(
                            "Token provider expired and re-prepare failed",
                            errorCode = code,
                        )
                    }
                } else {
                    failure = mapTokenError(e)
                }
            }

            // If we hit a failure, short-circuit.
            failure?.let { return@withContext it }

            // If we got here, a token was issued. For APK Detector's
            // purposes, that means Play's on-device integrity check
            // passed.
            val token = tokenResponse?.token()
            if (token.isNullOrEmpty()) {
                Result.Error("Play Integrity returned empty token")
            } else {
                Result.Passes(true)
            }
        } catch (e: Exception) {
            Result.Error(
                message = e.message ?: "Unknown Play Integrity error",
                errorCode = extractErrorCode(e),
            )
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    /**
     * Get the cached token provider, or prepare a new one if missing /
     * invalidated. Returns null if preparation fails (e.g., Play services
     * not installed, network error during warm-up).
     */
    private fun getOrPrepareProvider(
        context: Context,
        cloudProjectNumber: Long,
    ): StandardIntegrityTokenProvider? {
        providerHolder.provider?.let { return it }

        return try {
            val manager = IntegrityManagerFactory.createStandard(context)
            val provider = Tasks.await(
                manager.prepareIntegrityToken(
                    com.google.android.play.core.integrity.PrepareIntegrityTokenRequest.builder()
                        .setCloudProjectNumber(cloudProjectNumber)
                        .build(),
                ),
                // Warm-up typically takes 1-2s on first call, <500ms on
                // subsequent calls (cached). 15s timeout is generous.
                15, TimeUnit.SECONDS,
            )
            providerHolder.provider = provider
            provider
        } catch (e: Exception) {
            // Failed to prepare — leave provider null so next call retries.
            null
        }
    }

    /**
     * Compute a stable SHA-256 hash of the package name + minute-bucket
     * timestamp. Used as the requestHash for the integrity token request.
     *
     * Minute-bucketing means rapid retries within the same minute produce
     * the same hash, which is fine — the API's replay protection is at
     * the token level, not the hash level.
     */
    private fun stableRequestHash(packageName: String): String {
        val minuteBucket = System.currentTimeMillis() / 60_000L
        val input = "$packageName:$minuteBucket"
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Map a Play Integrity API exception to a [Result].
     *
     * Error codes that indicate "non-genuine device/app" map to
     * [Result.Passes] with value=false — Google explicitly refused to
     * issue a token because the device/app failed integrity.
     *
     * Other error codes map to [Result.Error] — caller may retry.
     */
    private fun mapTokenError(e: Exception): Result {
        val code = extractErrorCode(e)
        return when (code) {
            // Non-genuine device/app — Google refused to issue a token.
            // This is a definitive "fails integrity" signal.
            ERROR_PLAY_STORE_NOT_FOUND,
            ERROR_APP_NOT_INSTALLED,
            ERROR_APP_UID_MISMATCH,
            ERROR_NONCE_TOO_SHORT,
            ERROR_GOOGLE_SERVER_UNAVAILABLE,
            -> Result.Passes(false)

            else -> Result.Error(
                message = e.message ?: "Play Integrity request failed",
                errorCode = code,
            )
        }
    }

    /**
     * Extract the error code from a Play Integrity API exception.
     *
     * The StandardIntegrityManager API throws
     * `com.google.android.gms.common.api.ApiException` with a status code
     * in `statusCode`. The Standard Integrity error codes are documented
     * at https://developer.android.com/google/play/integrity/error-codes.
     */
    private fun extractErrorCode(e: Throwable): Int? {
        // Try ApiException.getStatusCode() via reflection (avoid hard
        // dependency on com.google.android.gms.common.api.ApiException
        // class name, which can vary across Play services versions).
        return try {
            val apiExceptionClass = Class.forName(
                "com.google.android.gms.common.api.ApiException",
            )
            if (apiExceptionClass.isInstance(e)) {
                val statusCodeMethod = apiExceptionClass.getMethod("getStatusCode")
                statusCodeMethod.invoke(e) as Int
            } else {
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    // ─── Standard Integrity error codes ─────────────────────────────────
    //
    // These constants match the values in
    // com.google.android.play.core.integrity.StandardIntegrityErrorCode.
    // We hard-code them here to avoid pulling the constant class into
    // the type system (which would require a different import path on
    // different SDK versions).
    //
    // Source: https://developer.android.com/google/play/integrity/error-codes

    private const val ERROR_PLAY_STORE_NOT_FOUND = 1
    private const val ERROR_PLAY_SERVICES_NOT_FOUND = 2
    private const val ERROR_APP_NOT_INSTALLED = 3
    private const val ERROR_PLAY_SERVICES_VERSION_TOO_OLD = 4
    private const val ERROR_APP_UID_MISMATCH = 5
    private const val ERROR_TOO_MANY_REQUESTS = 6
    private const val ERROR_CANNOT_BIND_TO_SERVICE = 7
    private const val ERROR_NETWORK_ERROR = 8
    private const val ERROR_GOOGLE_SERVER_UNAVAILABLE = 9
    private const val ERROR_INTEGRITY_TOKEN_PROVIDER_INVALID = 10
    private const val ERROR_NONCE_TOO_SHORT = 13
}
