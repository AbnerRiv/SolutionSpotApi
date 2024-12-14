using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace api.Helpers
{
    public class ApiDecryptor
    {
        public static string DecryptString(string cipherText, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = new byte[16]; // Same IV as used during encryption

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new StreamReader(cs);
            return reader.ReadToEnd();
        }
    }
}