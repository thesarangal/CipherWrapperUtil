import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.*
import android.util.Base64.*
import java.nio.charset.StandardCharsets.UTF_8
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.inject.Inject

/**
 * Class used to Encrypt/Decrypt Data
 *
 * @author Rajat Sarangal
 * @since December 12, 2021
 * */
class CiperWrapperUtil @Inject constructor(transformation: String) {

    companion object {
        const val TRANSFORMATION_ASYMMETRIC = "$KEY_ALGORITHM_RSA/$BLOCK_MODE_ECB/$ENCRYPTION_PADDING_RSA_PKCS1"
        const val TRANSFORMATION_SYMMETRIC = "$KEY_ALGORITHM_AES/$BLOCK_MODE_CBC/$ENCRYPTION_PADDING_PKCS7"
        const val IV_SEPARATOR = "]"
    }

    /**
     * The type of keystore.
     * See the KeyStore section in the <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     * for information about standard keystore types.
     * */
    private val provider = "AndroidKeyStore"

    // Cipher Instance
    private val cipher by lazy {
        Cipher.getInstance(transformation)
    }

    // String Transformation Format
    private val charset by lazy {
        UTF_8
    }

    // Storage facility for cryptographic keys and certificates
    private val keyStore by lazy {
        KeyStore.getInstance(provider).apply {
            load(null)
        }
    }

    // Secret (symmetric) Key Generator
    private val keyGenerator by lazy {
        KeyGenerator.getInstance(KEY_ALGORITHM_AES, provider)
    }

    /**
     * Encrypt Data
     *
     * @param alias     To Generate Secret Key
     * @param input     Data to Encrypt
     *
     * @return Pair of ByteArray: Encrypted and String: Ciper IV (which will be used in decryption)
     * */
    fun encrypt(alias: String, input: String): Pair<ByteArray, String> {
        cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(alias))
        val iv = cipher.iv
        val ivString = encodeToString(iv, DEFAULT)
        val bytes = cipher.doFinal(input.toByteArray(charset))
        return Pair(bytes, ivString)
    }

    /**
     * Decrypt Data
     *
     * @param alias     To Get Secret Key
     * @param input     Encrypted Data as ByteArray
     * @param ivString  Ciper IV (Which is generated during Encryption)
     *
     * @return Decrypted Data
     * */
    fun decrypt(alias: String, input: ByteArray, ivString: String): String {
        val ivSpec = IvParameterSpec(decode(ivString, DEFAULT))
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), ivSpec)
        return cipher.doFinal(input).toString(charset)
    }

    /**
     * Generate Secret Key
     *
     * @param keystoreAlias  alias of the entry in which the generated key will appear in Android KeyStore.
     *                       Must not be empty.
     * */
    private fun generateSecretKey(keystoreAlias: String): SecretKey {
        return keyGenerator.apply {
            init(
                KeyGenParameterSpec
                    .Builder(keystoreAlias, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
                    .setBlockModes(BLOCK_MODE_CBC)
                    .setEncryptionPaddings(ENCRYPTION_PADDING_PKCS7)
                    .build()
            )
        }.generateKey()
    }

    /**
     * Get Secret Key
     *
     * @param alias get the keystore Entry for this alias
     * 
     * @return Stored Secret Key from Key Store
     * */
    private fun getSecretKey(alias: String): SecretKey {
        return (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }
}
