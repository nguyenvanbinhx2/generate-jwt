using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace TestConjurAuthnAPIKey
{
    public class JWTGenerator
    {
        private static RSAParameters? _RSAParameters;
        private static X509Certificate2? _Certificate;

        private static string _Jwks = string.Empty;
        private static string _JwtToken = string.Empty;

        private static DateTime _ExpireToken = DateTime.MinValue;

        /// <summary>
        /// Get Jwks file
        /// </summary>
        /// <returns></returns>
        public static string GetJwks()
        {
            return _Jwks;
        }

        /// <summary>
        /// Generate Token with time expire
        /// </summary>
        /// <returns></returns>
        public static string GenerateJwt()
        {
            if (IsValid()) return _JwtToken;
            var keyInfo = GenerateRsaKeyPair(2048);
            var keyId = Guid.NewGuid();
            var jwks = ConvertToJwks(keyInfo.certificate, keyId);

            _RSAParameters = keyInfo.privateKey;
            _Certificate = keyInfo.certificate;
            _Jwks = jwks;

            // Create RSA object from the private key parameters
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(_RSAParameters.Value);

                // Create security key using the RSA private key
                var privateKey = new RsaSecurityKey(rsa);
                // Create signing credentials using the private key
                var signingCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);
                signingCredentials.Key.KeyId = keyId.ToString();
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = "o365jwt",

                    Issuer = "https://jwt.o365-automation.fpt.com",
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new Claim("host", "OPSLConjurLeader"),
                        new Claim(JwtRegisteredClaimNames.Name, "o365jwt"),
                        new Claim(JwtRegisteredClaimNames.NameId, "o365jwt"),
                        new Claim(JwtRegisteredClaimNames.Sub, "user@example.com"),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = signingCredentials
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                // Write token to string
                _JwtToken = tokenHandler.WriteToken(token);
                _ExpireToken = DateTime.UtcNow.AddHours(0.5);
                return _JwtToken;
            }
        }

        /// <summary>
        /// Generate rsa key and public 
        /// </summary>
        /// <param name="keySize">Size of key</param>
        /// <returns></returns>
        private static (RSAParameters privateKey, X509Certificate2 certificate) GenerateRsaKeyPair(int keySize)
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                // Export the public and private key components
                var privateKey = rsa.ExportParameters(true);

                // Create X.509 certificate
                var request = new CertificateRequest(
                    new X500DistinguishedName($"CN=MyTestCert"),
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                // Set the validity period (valid from today to one year from today)
                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                DateTime notBefore = DateTime.UtcNow;
                // Create and self-sign the certificate
                X509Certificate2 certificate = request.CreateSelfSigned(notBefore, notBefore.AddYears(1));

                return (privateKey, certificate);
            }
        }

        /// <summary>
        /// Convert certificate to jwks
        /// </summary>
        /// <param name="certificate">public cert</param>
        /// <param name="keyId">keyid</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        private static string ConvertToJwks(X509Certificate2 certificate, Guid keyId)
        {
            RSA rsaPublicKey = certificate.GetRSAPublicKey();
            if (rsaPublicKey == null)
            {
                throw new ArgumentException("The provided certificate does not contain an RSA public key.");
            }

            RSAParameters publicKeyParams = rsaPublicKey.ExportParameters(false);

            var jwks = new
            {
                keys = new[]
                {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = keyId,
                    e = Base64UrlEncode(publicKeyParams.Exponent),
                    n = Base64UrlEncode(publicKeyParams.Modulus)
                }
            }
            };

            return JsonSerializer.Serialize(jwks, new JsonSerializerOptions { WriteIndented = true });
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        /// <summary>
        /// Check jwt must renew
        /// </summary>
        /// <returns></returns>
        private static bool IsValid()
        {
            if(_RSAParameters != null && !string.IsNullOrWhiteSpace(_Jwks) && !string.IsNullOrWhiteSpace(_JwtToken) && _ExpireToken >= DateTime.Now )
            {
                return true;
            }
            return false;
        }

    }
}
