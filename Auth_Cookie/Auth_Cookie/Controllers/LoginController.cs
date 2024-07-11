using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Auth_Cookie.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : Controller
    {
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (model.Username == "test" && model.Password == "password")
            {
                var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, model.Username)
        };

                var claimsIdentity = new ClaimsIdentity(claims, "CookieAutenticacion");

                await HttpContext.SignInAsync("CookieAutenticacion", new ClaimsPrincipal(claimsIdentity));

                return Ok();
            }

            return Unauthorized();
        }


        [HttpGet("accessdenied")]
        public IActionResult AccessDenied()
        {
            return Forbid();
        }
    }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}