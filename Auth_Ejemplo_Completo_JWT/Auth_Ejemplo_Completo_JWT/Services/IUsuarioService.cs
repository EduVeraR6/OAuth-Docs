using Auth_Ejemplo_Completo_JWT.Models;

namespace Auth_Ejemplo_Completo_JWT.Services
{
    public interface IUsuarioService
    {
        Usuario GetByUsername(string username);
        Usuario GetByRefreshToken(string token);
        void Update(Usuario user);
    }
}
