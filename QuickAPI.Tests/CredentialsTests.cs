using NUnit.Framework;
using QuickAPI.Configurations;
using QuickAPI.Security;
using System;
using System.Reflection;

namespace QuickAPI.Tests
{
    public class CredentialsTests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void EncryptStringTest()
        {
            var plainText = "Test Encode Text";
            var passPhrase = "User@123";

            var methodEncrypt = typeof(Credentials).GetMethod(
                "Encrypt",
                BindingFlags.Static | BindingFlags.NonPublic);

            var methodDecrypt = typeof(Credentials).GetMethod(
                "Decrypt",
                BindingFlags.Static | BindingFlags.NonPublic);

            var encryptedText = (string)methodEncrypt.Invoke(
                obj: null,
                parameters: new object[] { passPhrase, plainText });

            var decryptedText = (string)methodDecrypt.Invoke(
                obj: null,
                parameters: new object[] { passPhrase, encryptedText });

            Assert.AreEqual(plainText, decryptedText);

            plainText = "Test Encode Text";
            passPhrase = "User@1234";

            encryptedText = (string)methodEncrypt.Invoke(
                obj: null,
                parameters: new object[] { passPhrase, plainText });

            decryptedText = (string)methodDecrypt.Invoke(
                obj: null,
                parameters: new object[] { passPhrase, encryptedText });

            Assert.AreEqual(plainText, decryptedText);
        }

        [Test]
        public void CreateJwtTokenTest()
        {
            var methodCreateJwtToken = typeof(Credentials).GetMethod(
                "CreateJwtToken",
                BindingFlags.Static | BindingFlags.NonPublic);

            var authConfig = new AuthenticationConfiguration
            {
                AuthType = AuthType.Jwt,
                SecurityKey = "nOkmsc5B8HCzYLJVdC8UmuDhyxNLfzQeibAX9HKV"
            };

            var credentials = Activator.CreateInstance(
                typeof(Credentials),
                BindingFlags.NonPublic | BindingFlags.Instance,
                binder: null,
                args: new object[] { "postgres", "postgres" },
                culture: null);

            Assert.NotNull(credentials);

            var jwtToken = (JwtToken)methodCreateJwtToken.Invoke(
                obj: null,
                parameters: new object[] { authConfig, credentials });

            Assert.NotNull(jwtToken);
        }
    }
}