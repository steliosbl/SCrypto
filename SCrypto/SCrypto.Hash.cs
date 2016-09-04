namespace SCrypto.Hash
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    public static class SHA_256
    {
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