using Microsoft.AspNetCore.Http;
using QuickAPI.Exceptions;
using System;
using System.Net.Http.Headers;
using System.Text;

namespace QuickAPI
{
    public class Credentials
    {
        private Credentials(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public string Username { get; }

        public string Password { get; }

        public static Credentials Authenticate(HttpContext context)
        {
            if (context.Request.Headers.ContainsKey("Authorization"))
            {
                var authHeader = AuthenticationHeaderValue.Parse(context.Request.Headers["Authorization"]);

                if (authHeader.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase))
                {
                    var credentialParts = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':');

                    if (credentialParts.Length == 2)
                    {
                        return new Credentials(credentialParts[0], credentialParts[1]);
                    }
                }
            }

            throw new CredentialsException("Authentication failed");
        }
    }
}
