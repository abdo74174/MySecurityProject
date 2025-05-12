using Microsoft.AspNetCore.Mvc;
using SecureAuth.Models;
using SecureAuth.Services;

namespace SecureAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptionController : ControllerBase
    {
        private readonly EncryptionService _encryptionService;

        public EncryptionController(EncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        [HttpGet("generate-keys")]
        public IActionResult GenerateKeys()
        {
            var keys = _encryptionService.GenerateKeys();
            return Ok(new { PublicKey = keys.publicKey, PrivateKey = keys.privateKey });
        }

        [HttpPost("encrypt-and-store")]
        public IActionResult EncryptAndStore([FromBody] PlainTextRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Text))
                {
                    return BadRequest("Email and Text are required.");
                }

                var fileName = _encryptionService.EncryptAndStore(request.Email, request.Text);
                return Ok(new { Message = "Encrypted and saved.", File = fileName });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpGet("decrypt-from-file")]
        public IActionResult DecryptFromFile([FromQuery] string email)
        {
            try
            {
                var result = _encryptionService.DecryptFromFile(email);
                return Ok(new { DecryptedText = result });
            }
            catch (FileNotFoundException)
            {
                return NotFound("File not found.");
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }
 }
}