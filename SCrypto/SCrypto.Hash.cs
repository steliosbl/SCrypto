namespace SCrypto.Hash
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Contains methods that utilize the SHA256 hashing algorithm.
    /// </summary>
    public static class SHA_256
    {
        /// <summary>
        /// Calculate the SHA256 hash of the provided string and return it's digest.
        /// </summary>
        /// <param name="value">The string to be hashed.</param>
        /// <returns>The hash's digest.</returns>
        public static string GetDigest(string value)
        {
            using (SHA256 hash = SHA256Managed.Create())
            {
                return string.Join(
                   string.Empty,
                   hash.ComputeHash(Encoding.UTF8.GetBytes(value))
                  .Select(item => item.ToString("x2")));
            }
        }
    }
}