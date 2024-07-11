using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Server_Recursos.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ResourceController : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult GetAll()
        {
            return Ok(new { message = "Acceso permitido para usuarios autenticados" });
        }

        [HttpGet("admin")]
        [Authorize(Policy = "AdminOnly")]
        public IActionResult GetAdminData()
        {
            return Ok(new { message = "Acceso permitido solo para administradores" });
        }

        [HttpGet("user-or-admin")]
        [Authorize(Policy = "UserOrAdmin")]
        public IActionResult GetUserOrAdminData()
        {
            return Ok(new { message = "Acceso permitido para usuarios o administradores" });
        }
    }
}
