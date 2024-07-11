using Auth_JWT.Services;
using Microsoft.AspNetCore.Mvc;

namespace Auth_JWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
            private readonly JwtService _jwtService;

            public AuthController(JwtService jwtService)
            {
                _jwtService = jwtService;
            }

            [HttpPost("login")]
            public IActionResult Login([FromBody] LoginModel model)
            {
                // Aquí deberías verificar las credenciales del usuario contra una base de datos
                if (model.Username == "usuario" && model.Password == "contraseña")
                {
                    var token = _jwtService.GenerateToken(model.Username);
                    return Ok(new { token });
                }

                return Unauthorized();
            }

    }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}
