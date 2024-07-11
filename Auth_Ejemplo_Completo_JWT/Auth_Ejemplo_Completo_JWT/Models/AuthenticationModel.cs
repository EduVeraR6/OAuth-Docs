namespace Auth_Ejemplo_Completo_JWT.Models
{
    public class AuthenticationRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class AuthenticationResponse
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }

        public AuthenticationResponse( string token, string refreshToken)
        {
            Token = token;
            RefreshToken = refreshToken;
        }
    }

    public class RevokeTokenRequest
    {
        public string Token { get; set; }
    }
}
