namespace QuickAPI.Security
{
    public class JwtToken
    {
        public JwtToken(
            string token,
            string refreshToken)
        {
            Token = token;
            RefreshToken = refreshToken;
        }

        public string Token { get; }

        public string RefreshToken { get; }
    }
}
