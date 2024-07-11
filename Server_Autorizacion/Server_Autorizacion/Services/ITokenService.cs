using System.Security.Claims;

namespace Server_Autorizacion.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(IEnumerable<Claim> claims);
        string GenerateRefreshToken();
        DateTime GetRefreshTokenExpiration();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
