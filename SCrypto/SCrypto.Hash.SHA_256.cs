#region Copyright
// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SCrypto.Hash.SHA_256.cs">
//
// Copyright (C) 2016 Stelios Boulitsakis
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
// Email: styboulits@gmail.com
// </summary>
// --------------------------------------------------------------------------------------------------------------------
#endregion

/// <summary>
/// Collection of hashing methods.
/// </summary>
namespace SCrypto.Hash
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Contains methods that utilize the SHA256 hashing algorithm.
    /// </summary>
    public static class SHA_256
    {
        /// <summary>
        /// Calculate the SHA256 hash of the provided string and return it's digest.
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

            using (SHA256 hash = SHA256Managed.Create())
            {
                return string.Join(
                   string.Empty,
                   hash.ComputeHash(Encoding.UTF8.GetBytes(data))
                  .Select(item => item.ToString("x2")));
            }
        }
    }
}