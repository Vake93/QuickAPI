using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using QuickAPI.Configurations;
using QuickAPI.Exceptions;
using QuickAPI.Extensions;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace QuickAPI.Security
{
    public class Credentials
    {
        private const int _keysize = 128;
        private const int _derivationIterations = 1000;

        private const string _issuer = "quick.api.server";
        private const string _audience = "quick.api.users";
        private const string _securityToken = "quick.api.token";
        private const string _refreshToken = "quick.api.token.refresh";
        private const string _signingAlgorithm = SecurityAlgorithms.HmacSha256;

        private static readonly RNGCryptoServiceProvider _rngCryptoService = new RNGCryptoServiceProvider();
        private static readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        private Credentials(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public string Username { get; }

        public string Password { get; }

        public static async Task<JwtToken> LoginAsnc(HttpContext context, AuthenticationConfiguration authConfig)
        {
            if (authConfig.AuthType == AuthType.Jwt)
            {
                var credentials = await context.ReadModelAsync<Credentials>();
                return CreateJwtToken(authConfig, credentials);
            }

            throw new CredentialsException("Login failed");
        }

        public static async Task<JwtToken> RefreshTokenAsync(HttpContext context, AuthenticationConfiguration authConfig)
        {
            if (authConfig.AuthType == AuthType.Jwt)
            {
                var jwtToken = await context.ReadModelAsync<JwtToken>();

                if (jwtToken is JwtToken)
                {
                    var claims = JWTValidate(jwtToken.Token, authConfig);
                    var credentials = GetCredentials(authConfig, claims);

                    return CreateJwtToken(authConfig, credentials);
                }
            }

            throw new CredentialsException("Refresh token failed");
        }

        public static Credentials Authenticate(HttpContext context, AuthenticationConfiguration authConfig)
        {
            return authConfig.AuthType switch
            {
                AuthType.Basic => BasicAuthenticate(context),
                AuthType.Jwt => JWTAuthenticate(context, authConfig),
                _ => throw new CredentialsException("Authentication Type Unknown"),
            };
        }

        private static JwtToken CreateJwtToken(AuthenticationConfiguration authConfig, Credentials credentials)
        {
            if (credentials is null)
            {
                throw new CredentialsException("CreateJwtToken failed, credentials empty");
            }

            if (string.IsNullOrEmpty(authConfig.SecurityKey))
            {
                throw new CredentialsException("CreateJwtToken failed, SecurityKey empty");
            }

            var secretBytes = Encoding.UTF8.GetBytes(authConfig.SecurityKey);
            var symmetricSecurityKey = new SymmetricSecurityKey(secretBytes);
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, _signingAlgorithm);

            var refreshToken = GenerateRandomString();
            var securityToken = Encrypt(authConfig.SecurityKey, $"{credentials.Username}:{credentials.Password}");

            var claims = new Claim[]
            {
                    new Claim(_refreshToken, refreshToken),
                    new Claim(_securityToken, securityToken),
            };

            var jwtSecurityToken = new JwtSecurityToken(
                _issuer,
                _audience,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(60),
                claims: claims,
                signingCredentials: signingCredentials);

            return new JwtToken(
                _jwtSecurityTokenHandler.WriteToken(jwtSecurityToken),
                refreshToken);
        }

        private static Credentials BasicAuthenticate(HttpContext context)
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

            throw new CredentialsException("Credentials failed");
        }

        private static Credentials JWTAuthenticate(HttpContext context, AuthenticationConfiguration authConfig)
        {
            if (context.Request.Headers.ContainsKey("Authorization"))
            {
                var authHeader = AuthenticationHeaderValue.Parse(context.Request.Headers["Authorization"]);

                if (authHeader.Scheme.Equals("bearer", StringComparison.OrdinalIgnoreCase))
                {
                    var claims = JWTValidate(authHeader.Parameter, authConfig);
                    return GetCredentials(authConfig, claims);
                }
            }

            throw new CredentialsException("Credentials failed");
        }

        private static ClaimsPrincipal JWTValidate(string token, AuthenticationConfiguration authConfig)
        {
            try
            {
                if (string.IsNullOrEmpty(authConfig.SecurityKey))
                {
                    throw new CredentialsException("CreateJwtToken failed, SecurityKey empty");
                }

                var secretBytes = Encoding.UTF8.GetBytes(authConfig.SecurityKey);
                var symmetricSecurityKey = new SymmetricSecurityKey(secretBytes);

                var validationParameters = new TokenValidationParameters
                {
                    ClockSkew = TimeSpan.FromMinutes(5),
                    ValidAlgorithms = new string[] { _signingAlgorithm },
                    IssuerSigningKey = symmetricSecurityKey,
                    ValidAudience = _audience,
                    ValidIssuer = _issuer,
                    RequireSignedTokens = true,
                    RequireExpirationTime = true,
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                };

                return _jwtSecurityTokenHandler.ValidateToken(token, validationParameters, out _);
            }
            catch (SecurityTokenException)
            {
                throw new CredentialsException("Validate token failed");
            }
        }

        private static Credentials GetCredentials(AuthenticationConfiguration authConfig, ClaimsPrincipal claims)
        {
            if (string.IsNullOrEmpty(authConfig.SecurityKey))
            {
                throw new CredentialsException("CreateJwtToken failed, SecurityKey empty");
            }

            try
            {
                var tokenCliam = claims.FindFirst(_securityToken);

                if (tokenCliam is Claim)
                {
                    var credentialParts = Decrypt(authConfig.SecurityKey, tokenCliam.Value).Split(':');

                    if (credentialParts.Length == 2)
                    {
                        return new Credentials(credentialParts[0], credentialParts[1]);
                    }
                }

                throw new CredentialsException("Credentials failed");
            }
            catch (Exception)
            {
                throw new CredentialsException("Credentials failed");
            }
        }

        private static string Encrypt(string passPhrase, string plainText)
        {
            var saltStringBytes = Generate128BitsOfRandomEntropy();
            var ivStringBytes = Generate128BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            using var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, _derivationIterations);
            var keyBytes = password.GetBytes(_keysize / 8);

            using var symmetricKey = new RijndaelManaged
            {
                BlockSize = _keysize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            using var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();

            var encrptedBytes = memoryStream.ToArray();
            var cipherTextBytes = new byte[encrptedBytes.Length + saltStringBytes.Length + ivStringBytes.Length];

            Buffer.BlockCopy(saltStringBytes, 0, cipherTextBytes, 0, saltStringBytes.Length);
            Buffer.BlockCopy(ivStringBytes, 0, cipherTextBytes, saltStringBytes.Length, ivStringBytes.Length);
            Buffer.BlockCopy(encrptedBytes, 0, cipherTextBytes, saltStringBytes.Length + ivStringBytes.Length, encrptedBytes.Length);

            return Convert.ToBase64String(cipherTextBytes);
        }

        private static string Decrypt(string passPhrase, string cipherText)
        {
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText).AsSpan();
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Slice(0, _keysize / 8).ToArray();
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Slice(_keysize / 8, _keysize / 8).ToArray();
            var encrptedBytes = cipherTextBytesWithSaltAndIv.Slice((_keysize / 8) * 2).ToArray();

            using var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, _derivationIterations);
            var keyBytes = password.GetBytes(_keysize / 8);

            using var symmetricKey = new RijndaelManaged
            {
                BlockSize = _keysize,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            using var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes);
            using var memoryStream = new MemoryStream(encrptedBytes);
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            var plainTextBytes = new byte[encrptedBytes.Length];
            var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        private static byte[] Generate128BitsOfRandomEntropy()
        {
            var randomBytes = new byte[128 / 8];
            _rngCryptoService.GetBytes(randomBytes);
            return randomBytes;
        }

        private static string GenerateRandomString()
        {
            return Convert.ToBase64String(Generate128BitsOfRandomEntropy());
        }
    }
}
