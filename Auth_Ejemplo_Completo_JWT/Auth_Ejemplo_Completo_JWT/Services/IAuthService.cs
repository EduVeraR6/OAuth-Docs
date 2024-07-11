using Auth_Ejemplo_Completo_JWT.Models;

namespace Auth_Ejemplo_Completo_JWT.Services
{
    public interface IAuthService
    {
        AuthenticationResponse Authenticate(AuthenticationRequest model, string ipAddress);
        AuthenticationResponse RefreshToken(string token, string ipAddress);
        bool RevokeToken(string token, string ipAddress);
    }
}
