using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Server_Autorizacion.Models;
using Server_Autorizacion.Services;

namespace Server_Autorizacion.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly TokenService _tokenService;
        private static Dictionary<string, string> refreshTokens = new Dictionary<string, string>(); // Este diccionario debe reemplazarse por un almacenamiento persistente

        public AuthController(IConfiguration configuration, TokenService tokenService)
        {
            _configuration = configuration;
            _tokenService = tokenService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            // Validar las credenciales del usuario (esto debería ser reemplazado por una validación real)
            if (model.Username == "admin" && model.Password == "password")
            {
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, "admin"),
                    new Claim(ClaimTypes.Role, "Admin")
                };

                var accessToken = _tokenService.GenerateAccessToken(claims);
                var refreshToken = _tokenService.GenerateRefreshToken();
                refreshTokens[refreshToken] = "admin"; // Almacenar el refresh token junto con el usuario

                return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
            }
            else if (model.Username == "user" && model.Password == "password")
            {
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, "user"),
                    new Claim(ClaimTypes.Role, "User")
                };

                var accessToken = _tokenService.GenerateAccessToken(claims);
                var refreshToken = _tokenService.GenerateRefreshToken();
                refreshTokens[refreshToken] = "user"; // Almacenar el refresh token junto con el usuario

                return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
            }
            return Unauthorized();
        }

        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] TokenModel refreshTokenRequest)
        {
            if (refreshTokenRequest == null || string.IsNullOrEmpty(refreshTokenRequest.RefreshToken))
                return BadRequest("Invalid client request");

            var principal = _tokenService.GetPrincipalFromExpiredToken(refreshTokenRequest.AccessToken);
            var username = principal.Identity.Name;

            if (!refreshTokens.TryGetValue(refreshTokenRequest.RefreshToken, out var storedUsername) || storedUsername != username)
                return BadRequest("Invalid client request");

            var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            refreshTokens.Remove(refreshTokenRequest.RefreshToken);
            refreshTokens[newRefreshToken] = username;

            return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
        }

        [HttpPost("revoke")]
        public IActionResult Revoke([FromBody] TokenModel refreshTokenRequest)
        {
            if (refreshTokenRequest == null || string.IsNullOrEmpty(refreshTokenRequest.RefreshToken))
                return BadRequest("Invalid client request");

            refreshTokens.Remove(refreshTokenRequest.RefreshToken);
            return NoContent();
        }
    }
}
