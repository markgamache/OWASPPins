using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;

using CreativeCode.JWS;
using CreativeCode.JWK;
using CreativeCode.JWK.KeyParts;



namespace Pinning
{
    internal class Program
    {
        static void Main(string[] args)
        {



            JwkLibrary xs = new JwkLibrary();

            string publicKeyXml = "";
            string privateKeyXml = "";

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                // Export public and private keys to XML format
                publicKeyXml = rsa.ToXmlString(false);
                privateKeyXml = rsa.ToXmlString(true);


            }


            string theJWS = JwsLibrary.CreateJws("load of pay", privateKeyXml);
            Console.WriteLine(theJWS);
            
            bool pass =  JwsLibrary.VerifyJws(theJWS, publicKeyXml);

            ECDsa startKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ECDsaSecurityKey key = new ECDsaSecurityKey(startKey);

            JsonWebKey jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

            //RSA rsa = RSA.Create();

            // Create a JSON Web Key (JWK) from the RSA key pair
            //var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa));

            // Create JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                new System.Security.Claims.Claim("user_id", "12345"),
                new System.Security.Claims.Claim("username", "john_doe"),
            }),
                // Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    jwk, SecurityAlgorithms.EcdsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            // Serialize the JWS
            var jws = tokenHandler.WriteToken(token);

            // Output the JWK and JWS
            Console.WriteLine($"JWK:\n{jwk}\n");
            Console.WriteLine($"JWS:\n{jws}");




            Console.WriteLine("Implementation of RFC7515 (JSON Web Signature)");

            /*

            // A signature key (RSA/EC/OCT) is needed. This implementation always uses JWKs (RFC7517) to supply a key.
            var keyUse = PublicKeyUse.Signature;
            var keyOperations = new HashSet<KeyOperation>(new[] { KeyOperation.ComputeDigitalSignature, KeyOperation.VerifyDigitalSignature });
            var algorithm = Algorithm.ES256;
            //var jwk = new JWK(algorithm, keyUse, keyOperations);
            var jwk = new JWK(algorithm);

            Console.WriteLine(jwk.ToString());

            // Provide custom Content-Type and content. "application/fhir+json" is only choosen as an example.
            // Create header based on supplied information. Exceptions may be thrown if required content is not proivided by the JWKProvider
            var joseHeader = new ProtectedJoseHeader(jwk, "application/fhir+json", SerializationOption.JwsCompactSerialization);
            var payload = Encoding.UTF8.GetBytes("payloadData");

            // Initialize JWS
            var jws = new JWS(new[] { joseHeader }, payload);
            
            //var jws = new JWS(null, payload);

            // Create digital signature
            jws.CalculateSignature();
            var jwsSignature = jws.Export();

            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("Created JSON Web Signature: " + jwsSignature);
            */


            Console.WriteLine("");
        }
    }
}
