#region Copyright
// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SCrypto.PGP.SPGP.cs">
//
// Copyright (C) 2016 Stelio Logothetis
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
// </copyright>
// <summary>
// SCrypto cryptographic function library for C#.
// Email: stel.logothetis@gmail.com
// </summary>
// --------------------------------------------------------------------------------------------------------------------
#endregion

/// <summary>
/// Collection of classes and methods pertaining to the PGP cryptographic standard.
/// </summary>
namespace SCrypto.PGP
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Implementation of the PGP algorithm that utilizes RSA and AES-256.
    /// </summary>
    public class SPGP
    {
        /// <summary>
        /// The length of all generated session keys.
        /// </summary>
        public const int SessionKeyLength = 64;

        /// <summary>
        /// Initializes a new instance of the <see cref="SPGP"/> class.
        /// </summary>
        public SPGP()
        {
            this.CreateKeyPair();
            this.SessionKey = null;
            this.EncryptedSessionKey = null;
            this.ClearText = null;
            this.CipherText = null;
            this.RecipientPublicKey = null;
        }

        /// <summary>
        /// Gets the public key (generated).
        /// </summary>
        public string PublicKey { get; private set; }

        /// <summary>
        /// Gets the private key (generated).
        /// </summary>
        public string PrivateKey { get; private set; }

        /// <summary>
        /// Gets the session key (generated).
        /// </summary>
        public string SessionKey { get; private set; }

        /// <summary>
        /// Gets the session key, encrypted with the recipient's public key.
        /// </summary>
        public byte[] EncryptedSessionKey { get; private set; }

        /// <summary>
        /// Gets the unencrypted text (can be provided by the user or through decryption of cipher text).
        /// </summary>
        public string ClearText { get; private set; }

        /// <summary>
        /// Gets the encrypted text (can be provided by the user or through encryption of clear text).
        /// </summary>
        public string CipherText { get; private set; }

        /// <summary>
        /// Gets or sets the recipient's public key (used to encrypt the session key).
        /// </summary>
        public string RecipientPublicKey { get; set; }

        /// <summary>
        /// Encrypt the given text using a generated session key, which is in turn encrypted using the provided public key.
        /// </summary>
        /// <param name="text">The text to be encrypted.</param>
        /// <param name="recipientPublicKey">The key that will be used to encrypt the session key.</param>
        /// <returns>The encrypted text.</returns>
        public string Encrypt(string text, string recipientPublicKey)
        {
            // User error checks
            if (text == null || text == string.Empty)
            {
                throw new ArgumentException("Text required!", "text");
            }

            if (recipientPublicKey == null || recipientPublicKey == string.Empty)
            {
                throw new ArgumentException("Recipient's public key required!", "recipientPublicKey");
            }

            this.RecipientPublicKey = recipientPublicKey;
            this.ClearText = text;
            this.EncryptClearText();
            return this.CipherText;
        }

        /// <summary>
        /// Decrypt the given session key using own private key, then use it to decrypt given cipher text.
        /// </summary>
        /// <param name="text">The cipher text to be decrypted.</param>
        /// <param name="encryptedSessionkey">The (encrypted) session key.</param>
        /// <returns>The decrypted text.</returns>
        public string Decrypt(string text, byte[] encryptedSessionkey)
        {
            // User error checks
            if (string.IsNullOrWhiteSpace(text))
            {
                throw new ArgumentException("Encrypted text required!", "text");
            }

            if (encryptedSessionkey == null || encryptedSessionkey.Length == 0)
            {
                throw new ArgumentException("Encrypted session key required!", "encryptedSessionkey");
            }

            this.EncryptedSessionKey = encryptedSessionkey;
            this.CipherText = text;
            this.DecryptCipherText();
            return this.ClearText;
        }

        /// <summary>
        /// Generate a session key, use it to encrypt the ClearText and then encrypt it using the RecipientPublicKey.
        /// </summary>
        private void EncryptClearText()
        {
            this.CreateSessionKey();
            this.EncryptedSessionKey = SCrypto.Asymmetric.RSA.Encrypt(this.RecipientPublicKey, this.SessionKey);
            this.CipherText = SCrypto.Symmetric.AES256WithHMAC.SimpleEncryptWithPassword(this.ClearText, this.SessionKey);
        }

        /// <summary>
        /// Decrypt the EncryptedSessionKey and use it to decrypt the CipherText.
        /// </summary>
        private void DecryptCipherText()
        {
            this.SessionKey = SCrypto.Asymmetric.RSA.Decrypt(this.PrivateKey, this.EncryptedSessionKey);
            this.ClearText = SCrypto.Symmetric.AES256WithHMAC.SimpleDecryptWithPassword(this.CipherText, this.SessionKey);
        }

        /// <summary>
        /// Generate an RSA public-private key pair.
        /// </summary>
        private void CreateKeyPair()
        {
            var keys = SCrypto.Asymmetric.RSA.CreateKeyPair();
            this.PublicKey = keys.Item1;
            this.PrivateKey = keys.Item2;
        }

        /// <summary>
        /// Securely generate a random session key.
        /// </summary>
        private void CreateSessionKey()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[256];
                rng.GetBytes(tokenData);

                this.SessionKey = SCrypto.Hash.SHA_256.GetDigest(Convert.ToBase64String(tokenData));
            }
        }
    }
}
