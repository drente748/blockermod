package com.blockermod.platform.vpn

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/** CI, signed release and shipped license notices must exist in the repository (B11). */
class ReleaseInfrastructureTest {

    @Test
    fun `android CI runs instrumented tests and keeps the grep guards`() {
        val workflow = repoFile(".github/workflows/android.yml").readText()

        assertTrue(workflow.contains("connectedDebugAndroidTest"))
        assertTrue(workflow.contains("android-emulator-runner"))
        for (guard in listOf("AF_INET6", "UDP_DOQ_853", "WakeLock", "Thread\\.sleep")) {
            assertTrue(workflow.contains(guard.toRegex()) || workflow.contains(guard), "missing CI guard: $guard")
        }
    }

    @Test
    fun `the release workflow signs from secrets and never commits the key`() {
        val workflow = repoFile(".github/workflows/release.yml").readText()

        assertTrue(workflow.contains("assembleRelease"))
        assertTrue(workflow.contains("RELEASE_KEYSTORE_BASE64"))
        assertTrue(workflow.contains("RELEASE_KEYSTORE_PASSWORD"))
        assertTrue(workflow.contains("upload-artifact"))
    }

    @Test
    fun `license texts ship inside the app assets`() {
        for (name in listOf("Apache-2.0.txt", "MIT.txt", "GPL-3.0.txt")) {
            val text = repoFile("app/src/main/assets/licenses/$name").readText()
            assertTrue(text.length > 500, "$name must contain the real license text")
        }
    }

    @Test
    fun `the key backup procedure is documented`() {
        assertTrue(repoFile("docs/KEY_BACKUP.md").readText().contains("RELEASE_KEYSTORE_BASE64"))
    }

    private fun repoFile(path: String): File {
        var directory: File? = File(System.getProperty("user.dir"))
        while (directory != null) {
            val candidate = File(directory, path)
            if (candidate.isFile) return candidate
            directory = directory.parentFile
        }
        throw AssertionError("missing repository file: $path")
    }
}
