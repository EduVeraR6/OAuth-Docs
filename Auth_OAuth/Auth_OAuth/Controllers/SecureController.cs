using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth_OAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : Controller
    {
        [Authorize]
        [HttpGet]
        public IActionResult Get()
        {
            return Ok($"Hello, {User.Identity.Name}! You've accessed a secure endpoint.");
        }
    }
}
