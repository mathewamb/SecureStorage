package com.example.securestorage




import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File
import java.nio.charset.Charset
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SecureStorageDemo()
        }
    }
}

@Composable
fun SecureStorageDemo() {
    val context = LocalContext.current

    var keystoreMessage by remember { mutableStateOf("") }
    var sharedPrefsMessage by remember { mutableStateOf("") }
    var fileMessage by remember { mutableStateOf("") }

    Column(modifier = Modifier.padding(16.dp)) {

        Button(
            onClick = { keystoreMessage = keystoreEncryptDecryptDemo() },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
        ) {
            Text("Test Android Keystore")
        }
        Text(keystoreMessage, modifier = Modifier.padding(bottom = 16.dp))


        Button(
            onClick = { sharedPrefsMessage = encryptedSharedPrefsDemo(context) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
        ) {
            Text("Test EncryptedSharedPreferences")
        }
        Text(sharedPrefsMessage, modifier = Modifier.padding(bottom = 16.dp))


        Button(
            onClick = { fileMessage = encryptedFileDemo(context) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
        ) {
            Text("Test EncryptedFile")
        }
        Text(fileMessage)

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { keystoreMessage = ""; sharedPrefsMessage = ""; fileMessage = "" },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
        ) {
            Text("Reset")
        }
    }
}

// ----------- ANDROID KEYSTORE DEMO -----------
fun keystoreEncryptDecryptDemo(): String {
    return try {
        val keyAlias = "myKeyAlias"
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        // Generate key if it doesn't exist
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val parameterSpec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            keyGenerator.init(parameterSpec)
            keyGenerator.generateKey()
        }

        val secretKey = keyStore.getKey(keyAlias, null) as? SecretKey
            ?: return "Key generation/retrieval failed"

        val plainText = "Hello Secure World!"
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plainText.toByteArray(Charset.defaultCharset()))

        // Decrypt
        val cipher2 = Cipher.getInstance("AES/GCM/NoPadding")
        cipher2.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val decrypted = cipher2.doFinal(encrypted)

        "Original: $plainText\nDecrypted: ${String(decrypted)}"
    } catch (e: Exception) {
        "Keystore error: ${e.message}"
    }
}

// ----------- ENCRYPTED SHARED PREFERENCES DEMO -----------
fun encryptedSharedPrefsDemo(context: Context): String {
    try {
        // Delete the corrupted file on every run (for demo/dev only!)
        val prefsFile = File(context.filesDir.parent + "/shared_prefs/secret_shared_prefs.xml")
        if (prefsFile.exists()) prefsFile.delete()
    } catch (_: Exception) { /* ignore */ }

    return try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val sharedPreferences = EncryptedSharedPreferences.create(
            context,
            "secret_shared_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        // Always overwrite for demo
        val secretToken = "TopSecretToken123"
        sharedPreferences.edit().putString("secret_token", secretToken).commit() // Use commit!

        // Read after write
        val token = sharedPreferences.getString("secret_token", "N/A")
        if (token == null || token == "N/A") {
            "Error: Value not written or read!"
        } else {
            "Stored & Read from EncryptedSharedPreferences:\n$token"
        }
    } catch (e: Exception) {
        "EncryptedSharedPreferences error: ${e.message}"
    }
}


// ----------- ENCRYPTED FILE DEMO -----------
fun encryptedFileDemo(context: Context): String {
    return try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val file = File(context.filesDir, "secret_data.txt")

        // Delete old file if it exists (for demo/dev only!)
        if (file.exists()) file.delete()

        val encryptedFile = EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()

        // Write to encrypted file
        val dataToWrite = "This is top secret file data!"
        encryptedFile.openFileOutput().use { output ->
            output.write(dataToWrite.toByteArray())
        }

        // Now read
        val result = encryptedFile.openFileInput().use { input ->
            input.readBytes().toString(Charset.defaultCharset())
        }

        if (result.isEmpty()) {
            "Error: File written but could not read back!"
        } else {
            "EncryptedFile read data:\n$result"
        }
    } catch (e: Exception) {
        "EncryptedFile error: ${e.message}"
    }
}

