using Microsoft.AspNetCore.Mvc;
using SecureAuth.Models;
using SecureAuth.Services;

namespace SecureAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserService _userService;

        public AuthController(UserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public IActionResult Register(User user)
        {
            bool success = _userService.Register(user);
            if (!success) return Conflict("User already exists.");
            return Ok("Registered successfully.");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] User loginData)
        {
            var user = _userService.Authenticate(loginData.Email, loginData.PasswordHash);
            if (user == null) return Unauthorized("Invalid email or password.");
            return Ok("Login successful.");
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword([FromBody] ResetPass request)
        {
            bool success = _userService.ResetPassword(request.Email, request.NewPassword);
            if (!success) return NotFound("User not found.");
            return Ok("Password reset successfully.");
        }

        [HttpPost("change-password")]
        public IActionResult ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
            {
                return BadRequest("Email, CurrentPassword, and NewPassword are required.");
            }

            bool success = _userService.ChangePassword(request.Email, request.CurrentPassword, request.NewPassword);
            if (!success) return Unauthorized("Invalid credentials.");
            return Ok("Password changed successfully.");
        }
    }
}