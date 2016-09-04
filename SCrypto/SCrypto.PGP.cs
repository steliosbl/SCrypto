namespace SCrypto.PGP
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    public class PGP
    {
        public PGP()
        {
            this.CreateKeyPair();
            this.SessionKey = null;
            this.EncryptedSessionKey = null;
            this.ClearText = null;
            this.CipherText = null;
            this.RecipientPublicKey = null;
        }

        public string PublicKey { get; private set; }

        public string PrivateKey { get; private set; }

        public string SessionKey { get; private set; }

        public byte[] EncryptedSessionKey { get; private set; }

        public string ClearText { get; private set; }

        public string CipherText { get; private set; }

        public string RecipientPublicKey { get; set; }

        public string Encrypt(string text, string recipientPublicKey)
        {
            this.RecipientPublicKey = recipientPublicKey;
            this.ClearText = text;
            this.EncryptClearText();
            return this.CipherText;
        }

        public string Decrypt(string text, byte[] encryptedSessionkey)
        {
            this.EncryptedSessionKey = encryptedSessionkey;
            this.CipherText = text;
            this.DecryptCipherText();
            return this.ClearText;
        }

        private void EncryptClearText()
        {
            this.CreateSessionKey();
            this.CipherText = Crypto.Symmetric.AESThenHMAC.SimpleEncryptWithPassword(this.ClearText, this.SessionKey);
            this.EncryptedSessionKey = Crypto.Asymmetric.RSA.Encrypt(this.RecipientPublicKey, this.SessionKey);
        }

        private void DecryptCipherText()
        {
            this.SessionKey = Crypto.Asymmetric.RSA.Decrypt(this.PrivateKey, this.EncryptedSessionKey);
            this.ClearText = Crypto.Symmetric.AESThenHMAC.SimpleDecryptWithPassword(this.CipherText, this.SessionKey);
        }

        private void CreateKeyPair()
        {
            var keys = Crypto.Asymmetric.RSA.CreateKeyPair();
            this.PublicKey = keys.Item1;
            this.PrivateKey = keys.Item2;
        }

        private void CreateSessionKey()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[256];
                rng.GetBytes(tokenData);

                this.SessionKey = Crypto.Hash.SHA_256.GetDigest(Convert.ToBase64String(tokenData));
            }
        }
    }
}
