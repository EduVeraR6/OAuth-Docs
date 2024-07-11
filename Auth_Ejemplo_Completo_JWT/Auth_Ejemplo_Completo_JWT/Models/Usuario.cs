namespace Auth_Ejemplo_Completo_JWT.Models
{
    //Modelo de datos para el usuario
    public class Usuario
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string Role { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

        public Usuario(int id, string username, string passwordHash, string role)
        {
            Id = id;
            Username = username;
            PasswordHash = passwordHash;
            Role = role;
        }

    }
}
