using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IS4.AuthorizationCenter.Models.Options;
using Microsoft.Extensions.Options;

namespace IS4.AuthorizationCenter.Extensions.Security
{
    /// <summary>
    /// Aes加密类
    /// </summary>
    public class AesSecurity
    {
        private readonly SecurityOption _securityOption;

        public AesSecurity(IOptionsMonitor<SecurityOption> securityOption)
        {
            _securityOption = securityOption.CurrentValue;
        }

        /// <summary>
        /// Aes解密
        /// </summary>
        /// <param name="input">解密内容</param>
        /// <returns></returns>
        public string AesDecrypt(string input)
        {
            var fullCipher = Convert.FromBase64String(input);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var decryptKey = Encoding.UTF8.GetBytes(_securityOption.AesKey);

            using var aesAlg = Aes.Create();
            if (aesAlg != null)
            {
                using var decryption = aesAlg.CreateDecryptor(decryptKey, iv);
                using var msDecrypt = new MemoryStream(cipher);
                using var csDecrypt = new CryptoStream(msDecrypt,
                    decryption, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                var result = srDecrypt.ReadToEnd();

                return result;
            }
            return "";
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="input">加密内容</param>
        /// <returns></returns>
        public string AesEncrypt(string input)
        {
            var encryptKey = Encoding.UTF8.GetBytes(_securityOption.AesKey);

            using var aesAlg = Aes.Create();
            if (aesAlg != null)
            {
                using var encryption = aesAlg.CreateEncryptor(encryptKey, aesAlg.IV);
                using var msEncrypt = new MemoryStream();
                using (var csEncrypt = new CryptoStream(msEncrypt, encryption,
                    CryptoStreamMode.Write))

                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(input);
                }

                var iv = aesAlg.IV;

                var decryptedContent = msEncrypt.ToArray();

                var result = new byte[iv.Length + decryptedContent.Length];

                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(decryptedContent, 0, result,
                    iv.Length, decryptedContent.Length);

                return Convert.ToBase64String(result);
            }

            return "";
        }

        /// <summary>
        /// Aes解密
        /// </summary>
        /// <param name="input">解密内容</param>
        /// <param name="key">加密Key</param>
        /// <returns></returns>
        public string AesDecrypt(string input, string key)
        {
            var fullCipher = Convert.FromBase64String(input);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var decryptKey = Encoding.UTF8.GetBytes(key);

            using var aesAlg = Aes.Create();
            if (aesAlg != null)
            {
                using var decryption = aesAlg.CreateDecryptor(decryptKey, iv);
                using var msDecrypt = new MemoryStream(cipher);
                using var csDecrypt = new CryptoStream(msDecrypt,
                    decryption, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                var result = srDecrypt.ReadToEnd();

                return result;
            }
            return "";
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="input">加密内容</param>
        /// <param name="key">加密Key</param>
        /// <returns></returns>
        public string AesEncrypt(string input, string key)
        {
            var encryptKey = Encoding.UTF8.GetBytes(key);

            using var aesAlg = Aes.Create();
            if (aesAlg != null)
            {
                using var encryption = aesAlg.CreateEncryptor(encryptKey, aesAlg.IV);
                using var msEncrypt = new MemoryStream();
                using (var csEncrypt = new CryptoStream(msEncrypt, encryption,
                    CryptoStreamMode.Write))

                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(input);
                }

                var iv = aesAlg.IV;

                var decryptedContent = msEncrypt.ToArray();

                var result = new byte[iv.Length + decryptedContent.Length];

                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(decryptedContent, 0, result,
                    iv.Length, decryptedContent.Length);

                return Convert.ToBase64String(result);
            }

            return "";
        }
    }
}