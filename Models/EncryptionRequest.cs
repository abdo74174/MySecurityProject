namespace SecureAuth.Models
{
    public class EncryptionRequest
    {
        public string Text { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public string PrivateKey { get; set; } = string.Empty;
    }
}
