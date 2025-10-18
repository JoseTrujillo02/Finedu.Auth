using Microsoft.AspNetCore.Mvc;
using FirebaseAdmin.Auth;

namespace FirebaseAuthApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        /// <summary>
        /// Crea un nuevo usuario en Firebase Authentication.
        /// </summary>
        [HttpPost("create")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest req)
        {
            var args = new UserRecordArgs()
            {
                Email = req.Email,
                EmailVerified = false,
                Password = req.Password,
                DisplayName = req.DisplayName,
                Disabled = false
            };

            try
            {
                var userRecord = await FirebaseAuth.DefaultInstance.CreateUserAsync(args);
                return Ok(new
                {
                    uid = userRecord.Uid,
                    email = userRecord.Email,
                    message = "Usuario creado correctamente"
                });
            }
            catch (FirebaseAuthException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }

    public record CreateUserRequest(string Email, string Password, string? DisplayName);
}
