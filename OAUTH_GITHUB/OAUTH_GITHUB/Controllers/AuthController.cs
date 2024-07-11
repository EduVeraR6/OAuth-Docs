using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace OAUTH_GITHUB.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login()
        {
            var properties = new AuthenticationProperties { RedirectUri = "/" };
            return Challenge(properties, "GitHub");
        }

        [HttpGet("logout")]
        public IActionResult Logout()
        {
            var properties = new AuthenticationProperties { RedirectUri = "/" };
            return SignOut(properties, CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
