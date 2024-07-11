using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("[controller]")]
public class SecureController : ControllerBase
{
    [Authorize]
    [HttpGet("user")]
    public IActionResult GetUserInfo()
    {
        var username = User.Identity?.Name;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;

        return Ok(new
        {
            Username = username,
            Role = role,
            Message = "Este endpoint es accesible para todos los usuarios autenticados"
        });
    }

    [Authorize(Policy = "AdminOnly")]
    [HttpGet("admin")]
    public IActionResult GetAdminInfo()
    {
        return Ok(new
        {
            Message = "Este endpoint es accesible solo para administradores"
        });
    }

    [Authorize(Policy = "UserOrAdmin")]
    [HttpGet("useradmin")]
    public IActionResult GetUserOrAdminInfo()
    {
        return Ok(new
        {
            Message = "Este endpoint es accesible para usuarios y administradores"
        });
    }
}