# CipherWrapperUtil
CipherWrapperUtil is a Kotlin class that can be used to encrypt/decrypt data using symmetric key cryptography. It is designed to work with Android KeyStore, which provides a secure storage facility for cryptographic keys and certificates. In general, The wrapper class for implementation for cryptography with CIPHER and Android Key Store.

## Usage
To use CipherWrapperUtil in your Android project, simply copy the CipherWrapperUtil class into your project and instantiate it with the desired cipher transformation (e.g. CipherWrapperUtil.TRANSFORMATION_SYMMETRIC).

### Encryption
To encrypt data, call the encrypt function with the alias of the entry in which the generated key will appear in Android KeyStore, and the data to encrypt as a string. The function will return a Pair containing the encrypted data as a ByteArray and the cipher IV as a String.

```bash
  val cipher = CipherWrapperUtil(CipherWrapperUtil.TRANSFORMATION_SYMMETRIC)
  val alias = "myAlias"
  val input = "secret message"
  val (encryptedData, iv) = cipher.encrypt(alias, input)
```

### Decryption
To decrypt data, call the decrypt function with the alias of the entry in which the generated key will appear in Android KeyStore, the encrypted data as a ByteArray, and the cipher IV generated during encryption as a String. The function will return the decrypted data as a string.

```bash
  val cipher = CipherWrapperUtil(CipherWrapperUtil.TRANSFORMATION_SYMMETRIC)
  val alias = "myAlias"
  val decryptedData = cipher.decrypt(alias, encryptedData, iv)
```

## Contributions

Contributions to this library are welcome. If you find a bug or have a feature request,
please open an issue on the [GitHub repository](https://github.com/thesarangal/CipherWrapperUtil).

## License

This library is released under the [MIT License](https://opensource.org/licenses/MIT).