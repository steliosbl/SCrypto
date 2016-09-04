namespace SCrypto.Symmetric
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Contains methods that perform AES256 and HMAC operations on data.
    /// </summary>
    public static class AESThenHMAC
    {
        // Preconfigured Encryption Parameters

        /// <summary>
        /// Default block bit size.
        /// </summary>
        public static readonly int BlockBitSize = 128;

        /// <summary>
        /// Default key bit size.
        /// </summary>
        public static readonly int KeyBitSize = 256;

        // Preconfigured Password Key Derivation Parameters

        /// <summary>
        /// Default salt bit size.
        /// </summary>
        public static readonly int SaltBitSize = 64;

        /// <summary>
        /// Default number of PBKDF2 iterations.
        /// </summary>
        public static readonly int Iterations = 10000;

        /// <summary>
        /// Default minimum password length.
        /// </summary>
        public static readonly int MinPasswordLength = 12;

        /// <summary>
        /// Secure random number generator.
        /// </summary>
        private static readonly RandomNumberGenerator Random = new RNGCryptoServiceProvider();

        /// <summary>
        /// Helper that generates a random key on each call.
        /// </summary>
        /// <returns>The generated key.</returns>
        public static byte[] NewKey()
        {
            var key = new byte[KeyBitSize / 8];
            Random.GetBytes(key);
            return key;
        }

        /// <summary>
        /// Simple Encryption (AES) then Authentication (HMAC) for a UTF8 Message.
        /// </summary>
        /// <remarks>
        /// Adds overhead of (Optional-Payload + BlockSize(16) + Message Padded To Block Size +  HMac-Tag(32)) * 1.33 Base64.
        /// </remarks>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="cryptKey">The crypt key.</param>
        /// <param name="authKey">The authentication key.</param>
        /// <param name="nonSecretPayload">Non-Secret Payload.</param>
        /// <exception cref="System.ArgumentException">Secret Message Required!;secretMessage.</exception>
        /// <returns>Encrypted Message.</returns>
        public static string SimpleEncrypt(string secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncrypt(plainText, cryptKey, authKey, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Simple Authentication (HMAC) then Decryption (AES) for a secrets UTF8 Message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="cryptKey">The crypt key.</param>
        /// <param name="authKey">The authentication key.</param>
        /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
        /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage.</exception>
        /// <returns>Decrypted Message.</returns>
        public static string SimpleDecrypt(string encryptedMessage, byte[] cryptKey, byte[] authKey, int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrWhiteSpace(encryptedMessage))
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            var cipherText = Convert.FromBase64String(encryptedMessage);
            var plainText = SimpleDecrypt(cipherText, cryptKey, authKey, nonSecretPayloadLength);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }

        /// <summary>
        /// Simple Encryption (AES) then Authentication (HMAC) of a UTF8 message
        /// using Keys derived from a Password (PBKDF2).
        /// </summary>
        /// <remarks>
        /// Significantly less secure than using random binary keys.
        /// Adds additional non secret payload for key generation parameters.
        /// </remarks>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayload">The non secret payload.</param>
        /// <exception cref="System.ArgumentException">Empty password.</exception>
        /// <returns>Encrypted Message.</returns>
        public static string SimpleEncryptWithPassword(string secretMessage, string password, byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncryptWithPassword(plainText, password, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Simple Authentication (HMAC) and then Decryption (AES) of a UTF8 Message
        /// using keys derived from a password (PBKDF2). 
        /// </summary>
        /// <remarks>Significantly less secure than using random binary keys.</remarks>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
        /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage.</exception>
        /// <returns>Decrypted Message.</returns>
        public static string SimpleDecryptWithPassword(string encryptedMessage, string password, int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrWhiteSpace(encryptedMessage))
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            var cipherText = Convert.FromBase64String(encryptedMessage);
            var plainText = SimpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }

        /// <summary>
        /// Performs the actual encryption operation on the data supplied.
        /// </summary>
        /// <param name="secretMessage">The data to be encrypted.</param>
        /// <param name="cryptKey">The encryption key.</param>
        /// <param name="authKey">The authentication key.</param>
        /// <param name="nonSecretPayload">The unencrypted payload to be bundled with the encrypted data.</param>
        /// <returns>The encrypted data.</returns>
        public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] cryptKey, byte[] authKey, byte[] nonSecretPayload = null)
        {
            // User Error Checks
            if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
            {
                throw new ArgumentException(string.Format("Key needs to be {0} bit!", KeyBitSize), "cryptKey");
            }

            if (authKey == null || authKey.Length != KeyBitSize / 8)
            {
                throw new ArgumentException(string.Format("Key needs to be {0} bit!", KeyBitSize), "authKey");
            }

            if (secretMessage == null || secretMessage.Length < 1)
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            // non-secret payload optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            byte[] cipherText;
            byte[] iv;

            using (var aes = new AesManaged
            {
                KeySize = KeyBitSize,
                BlockSize = BlockBitSize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                // Use random IV
                aes.GenerateIV();
                iv = aes.IV;

                using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
                using (var cipherStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cryptoStream))
                    {
                        // Encrypt Data
                        binaryWriter.Write(secretMessage);
                    }

                    cipherText = cipherStream.ToArray();
                }
            }

            // Assemble encrypted message and add authentication
            using (var hmac = new HMACSHA256(authKey))
            using (var encryptedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(encryptedStream))
                {
                    // Prepend non-secret payload if any
                    binaryWriter.Write(nonSecretPayload);

                    // Prepend IV
                    binaryWriter.Write(iv);

                    // Write Ciphertext
                    binaryWriter.Write(cipherText);
                    binaryWriter.Flush();

                    // Authenticate all data
                    var tag = hmac.ComputeHash(encryptedStream.ToArray());

                    // Postpend tag
                    binaryWriter.Write(tag);
                }

                return encryptedStream.ToArray();
            }
        }

        /// <summary>
        /// Performs the actual decryption operation on the given data.
        /// </summary>
        /// <param name="encryptedMessage">The data to be decrypted.</param>
        /// <param name="cryptKey">The decryption key.</param>
        /// <param name="authKey">The authentication key.</param>
        /// <param name="nonSecretPayloadLength">The length of the non-secret payload.</param>
        /// <returns>The decrypted data.</returns>
        public static byte[] SimpleDecrypt(byte[] encryptedMessage, byte[] cryptKey, byte[] authKey, int nonSecretPayloadLength = 0)
        {
            // Basic Usage Error Checks
            if (cryptKey == null || cryptKey.Length != KeyBitSize / 8)
            {
                throw new ArgumentException(string.Format("CryptKey needs to be {0} bit!", KeyBitSize), "cryptKey");
            }

            if (authKey == null || authKey.Length != KeyBitSize / 8)
            {
                throw new ArgumentException(string.Format("AuthKey needs to be {0} bit!", KeyBitSize), "authKey");
            }

            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            using (var hmac = new HMACSHA256(authKey))
            {
                var sentTag = new byte[hmac.HashSize / 8];

                // Calculate Tag
                var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
                var initializationVectorLength = BlockBitSize / 8;

                // if message length is to small just return null
                if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + initializationVectorLength)
                {
                    return null;
                }

                // Grab Sent Tag
                Array.Copy(encryptedMessage, encryptedMessage.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                // Compare Tag with constant time comparison
                var compare = 0;
                for (var i = 0; i < sentTag.Length; i++)
                {
                    compare |= sentTag[i] ^ calcTag[i];
                }

                // If message doesn't authenticate return null
                if (compare != 0)
                {
                    return null;
                }

                using (var aes = new AesManaged
                {
                    KeySize = KeyBitSize,
                    BlockSize = BlockBitSize,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7
                })
                {
                    // Grab IV from message
                    var iv = new byte[initializationVectorLength];
                    Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

                    using (var decrypter = aes.CreateDecryptor(cryptKey, iv))
                    using (var plainTextStream = new MemoryStream())
                    {
                        using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
                        using (var binaryWriter = new BinaryWriter(decrypterStream))
                        {
                            // Decrypt Cipher Text from Message
                            binaryWriter.Write(
                                encryptedMessage,
                                nonSecretPayloadLength + iv.Length,
                                encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length);
                        }

                        // Return Plain Text
                        return plainTextStream.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Simple Encryption (AES) then Authentication (HMAC) of a UTF8 message
        /// using Keys derived from a Password (PBKDF2).
        /// </summary>
        /// <remarks>
        /// Significantly less secure than using random binary keys.
        /// Adds additional non secret payload for key generation parameters.
        /// </remarks>
        /// <param name="secretMessage">The secret message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayload">The non secret payload.</param>
        /// <exception cref="System.ArgumentException">Empty password.</exception>
        /// <returns>Encrypted Message.</returns>
        public static byte[] SimpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
        {
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            // User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
            {
                throw new ArgumentException(string.Format("Must have a password of at least {0} characters!", MinPasswordLength), "password");
            }

            if (secretMessage == null || secretMessage.Length == 0)
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            var payload = new byte[((SaltBitSize / 8) * 2) + nonSecretPayload.Length];

            Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
            int payloadIndex = nonSecretPayload.Length;

            byte[] cryptKey;
            byte[] authKey;

            // Use Random Salt to prevent pre-generated weak password attacks.
            using (var generator = new Rfc2898DeriveBytes(password, SaltBitSize / 8, Iterations))
            {
                var salt = generator.Salt;

                // Generate Keys
                cryptKey = generator.GetBytes(KeyBitSize / 8);

                // Create Non Secret Payload
                Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
                payloadIndex += salt.Length;
            }

            // Deriving separate key, might be less efficient than using HKDF, 
            // but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
            using (var generator = new Rfc2898DeriveBytes(password, SaltBitSize / 8, Iterations))
            {
                var salt = generator.Salt;

                // Generate Keys
                authKey = generator.GetBytes(KeyBitSize / 8);

                // Create Rest of Non Secret Payload
                Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
            }

            return SimpleEncrypt(secretMessage, cryptKey, authKey, payload);
        }

        /// <summary>
        /// Simple Authentication (HMAC) and then Decryption (AES) of a UTF8 Message
        /// using keys derived from a password (PBKDF2). 
        /// </summary>
        /// <remarks>Significantly less secure than using random binary keys.</remarks>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="password">The password.</param>
        /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
        /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage.</exception>
        /// <returns>Decrypted Message.</returns>
        public static byte[] SimpleDecryptWithPassword(byte[] encryptedMessage, string password, int nonSecretPayloadLength = 0)
        {
            // User Error Checks
            if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
            {
                throw new ArgumentException(string.Format("Must have a password of at least {0} characters!", MinPasswordLength), "password");
            }

            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            var cryptSalt = new byte[SaltBitSize / 8];
            var authSalt = new byte[SaltBitSize / 8];

            // Grab Salt from Non-Secret Payload
            Array.Copy(encryptedMessage, nonSecretPayloadLength, cryptSalt, 0, cryptSalt.Length);
            Array.Copy(encryptedMessage, nonSecretPayloadLength + cryptSalt.Length, authSalt, 0, authSalt.Length);

            byte[] cryptKey;
            byte[] authKey;

            // Generate crypt key
            using (var generator = new Rfc2898DeriveBytes(password, cryptSalt, Iterations))
            {
                cryptKey = generator.GetBytes(KeyBitSize / 8);
            }

            // Generate auth key
            using (var generator = new Rfc2898DeriveBytes(password, authSalt, Iterations))
            {
                authKey = generator.GetBytes(KeyBitSize / 8);
            }

            return SimpleDecrypt(encryptedMessage, cryptKey, authKey, cryptSalt.Length + authSalt.Length + nonSecretPayloadLength);
        }
    }
}