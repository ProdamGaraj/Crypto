using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    class Program
    {
        private static readonly string Key = "KuplyGaraj";
        private static readonly string MacKey = "ProdamGaraj";
        private static readonly byte[] Salt = Encoding.UTF8.GetBytes("88005553535");

        private static byte[] Encrypt(byte[] data, string key)
        {
            using (var aes = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(key, Salt);

                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);
                aes.Padding = PaddingMode.Zeros;
                using (var mem = new MemoryStream())
                {
                    using (var crypt = new CryptoStream(mem, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        crypt.Write(data, 0, data.Length);
                        crypt.Close();
                    }
                    return mem.ToArray();
                }
            }
        }

        private static byte[] Decrypt(byte[] data, string key)
        {
            using (var aes = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(key, Salt);

                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                aes.Key = pdb.GetBytes(32);
                aes.IV = pdb.GetBytes(16);
                aes.Padding = PaddingMode.Zeros;
                using (var mem = new MemoryStream())
                {
                    using (var crypt = new CryptoStream(mem, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        crypt.Write(data, 0, data.Length);
                        crypt.Close();
                    }
                    return mem.ToArray();
                }
            }
        }

        static void Main(string[] args)
        {
            var imageBytes = File.ReadAllBytes("kartinka.jpg");
            var encrypted = Encrypt(imageBytes, Key);
            Console.WriteLine(encrypted.ToString());
            var decrypted = Decrypt(encrypted, Key);
            Console.WriteLine(decrypted.ToString());
            File.WriteAllBytes("kartinka1.jpg", decrypted);
        }
    }
}
