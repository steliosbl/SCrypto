namespace SPGP
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Contains methods that utilize the MD5 hashing algorithm.
    /// </summary>
    public static class MD_5
    {
        /// <summary>
        /// Calculate the MD5 hash of the provided string and return it's digest.
        /// </summary>
        /// <param name="data">The string to be hashed.</param>
        /// <returns>The hash's digest.</returns>
        public static string GetDigest(string data)
        {
            // User Error Checks
            if (data == null || data == string.Empty)
            {
                throw new ArgumentException("Data required!", "data");
            }

            using (MD5 hash = MD5CryptoServiceProvider.Create())
            {
                return string.Join(
                    string.Empty,
                    hash.ComputeHash(Encoding.UTF8.GetBytes(data))
                    .Select(item => item.ToString("x2")));
            }
        }
    }
}
