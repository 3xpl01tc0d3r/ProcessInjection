using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInjection.DInvoke.Native
{
    public static class Utils
    {
        /// <summary>
        /// Checks that a file is signed and has a valid signature.
        /// </summary>
        /// <param name="filePath">Path of file to check.</param>
        /// <returns></returns>
        public static bool FileHasValidSignature(string filePath)
        {
            X509Certificate2 fileCertificate;

            try
            {
                var signer = X509Certificate.CreateFromSignedFile(filePath);
                fileCertificate = new X509Certificate2(signer);
            }
            catch
            {
                return false;
            }

            var certificateChain = new X509Chain();
            certificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            certificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return certificateChain.Build(fileCertificate);
        }

        /// <summary>
        /// Generate an HMAC-MD5 hash of the supplied string using an Int64 as the key. This is useful for unique hash based API lookups.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="value">String to hash.</param>
        /// <param name="key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <returns>string, the computed MD5 hash value.</returns>
        public static string GetApiHash(string value, long key)
        {
            var data = Encoding.UTF8.GetBytes(value.ToLower());
            var bytes = BitConverter.GetBytes(key);

            var hmac = new HMACMD5(bytes);
            var bHash = hmac.ComputeHash(data);
            return BitConverter.ToString(bHash).Replace("-", "");
        }
    }
}
