using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureAuth.Services
{
    public class EncryptionService
    {
        private readonly string _storagePath = Path.Combine(Directory.GetCurrentDirectory(), "Data", "Encrypted");

        public EncryptionService()
        {
            if (!Directory.Exists(_storagePath))
                Directory.CreateDirectory(_storagePath);
        }

        public (string publicKey, string privateKey) GenerateKeys()
        {
            using var rsa = RSA.Create();
            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
            return (publicKey, privateKey);
        }

        public string EncryptAndStore(string email, string text)
        {
            using var rsa = RSA.Create();
            var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            var bytes = Encoding.UTF8.GetBytes(text);
            var encryptedBytes = rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256);
            var encryptedText = Convert.ToBase64String(encryptedBytes);

            var record = new
            {
                EncryptedText = encryptedText,
                PublicKey = publicKey,
                PrivateKey = privateKey
            };

            var fileName = email.Replace("@", "_at_").Replace(".", "_dot_") + ".json";
            var filePath = Path.Combine(_storagePath, fileName);
            File.WriteAllText(filePath, JsonSerializer.Serialize(record));

            return fileName;
        }

        public string DecryptFromFile(string email)
        {
            var fileName = email.Replace("@", "_at_").Replace(".", "_dot_") + ".json";
            var filePath = Path.Combine(_storagePath, fileName);
            if (!File.Exists(filePath)) throw new FileNotFoundException("Encrypted file not found.");

            var content = File.ReadAllText(filePath);
            var json = JsonDocument.Parse(content);
            var encryptedText = json.RootElement.GetProperty("EncryptedText").GetString();
            var privateKey = json.RootElement.GetProperty("PrivateKey").GetString();

            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey!), out _);
            var bytes = Convert.FromBase64String(encryptedText!);
            var decryptedBytes = rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);

            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public string Encrypt(string text, string publicKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
            var bytes = Encoding.UTF8.GetBytes(text);
            var encryptedBytes = rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(encryptedBytes);
        }

        public string Decrypt(string encryptedText, string privateKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
            var bytes = Convert.FromBase64String(encryptedText);
            var decryptedBytes = rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}