namespace SecureAuth.Models
{
    public class ResetPass
    {
        public string Email { get; set; } = string.Empty;

        public string NewPassword { get; set; } = string.Empty;
    }
}
