using Auth_Ejemplo_Completo_JWT.Models;

namespace Auth_Ejemplo_Completo_JWT.Services
{
    public class UsuarioService : IUsuarioService
    {
        private List<Usuario> _users = new List<Usuario>
    {
        new Usuario(1, "admin", BCrypt.Net.BCrypt.HashPassword("admin123"), "Admin"),
        new Usuario(2, "user", BCrypt.Net.BCrypt.HashPassword("user123"), "User")
    };

        public Usuario GetByUsername(string username)
        {
            return _users.SingleOrDefault(x => x.Username == username);
        }

        public Usuario GetByRefreshToken(string token)
        {
            return _users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
        }

        public void Update(Usuario user)
        {
        }
    }
}
