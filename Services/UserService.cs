using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureAuth.Models;

namespace SecureAuth.Services
{
    public class UserService
    {
        private readonly string _userDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Data", "Users");
        private readonly byte[] _key = Encoding.UTF8.GetBytes("Asran67890Ali4567890123456789012");
        private readonly byte[] _iv = Encoding.UTF8.GetBytes("Asran16-byte-iv!");

        public UserService()
        {
            if (!Directory.Exists(_userDirectory))
                Directory.CreateDirectory(_userDirectory);
        }

        private string GetUserFilePath(string email)
        {
            var fileName = email.Replace("@", "_at_").Replace(".", "_dot_") + ".json";
            return Path.Combine(_userDirectory, fileName);
        }

        public bool Register(User user)
        {
            string path = GetUserFilePath(user.Email);
            if (File.Exists(path)) return false;

            user.Email = EncryptText(user.Email);
            user.Name = EncryptText(user.Name);
            user.PasswordHash = HashPassword(user.PasswordHash);

            string json = JsonSerializer.Serialize(user);
            File.WriteAllText(path, json);
            return true;
        }

        public User Authenticate(string email, string password)
        {
            string path = GetUserFilePath(email);
            if (!File.Exists(path))
                return null;

            string json = File.ReadAllText(path);
            var user = JsonSerializer.Deserialize<User>(json);
            if (user != null && user.PasswordHash == HashPassword(password))
            {
                user.Email = DecryptText(user.Email);
                user.Name = DecryptText(user.Name);
                return user;
            }

            return null;
        }

        public bool ResetPassword(string email, string newPassword)
        {
            string path = GetUserFilePath(email);
            if (!File.Exists(path)) return false;

            string json = File.ReadAllText(path);
            var user = JsonSerializer.Deserialize<User>(json);
            if (user == null) return false;

            user.PasswordHash = HashPassword(newPassword);
            File.WriteAllText(path, JsonSerializer.Serialize(user));
            return true;
        }

        public bool ChangePassword(string email, string currentPassword, string newPassword)
        {
            var user = Authenticate(email, currentPassword);
            if (user == null) return false;

            return ResetPassword(email, newPassword);
        }

        private string HashPassword(string password)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(password);
            var hash = sha.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private string EncryptText(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using var sw = new StreamWriter(cs);
            sw.Write(plainText);
            sw.Close();
            return Convert.ToBase64String(ms.ToArray());
        }

        private string DecryptText(string cipherText)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
    }
}