using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.Security.Cryptography;
//using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text.Json;



namespace Pinning
{
    public class JwkLibrary
    {

          public static ECDsa CreateNewECDSA()
        {
            ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return ecdsa;
        }

        /// <summary>
        /// Takes the json of a JWK and creates an ECdsa, per https://openid.net/specs/draft-jones-json-web-key-03.html
        /// </summary>
        /// <param name="jwkJson">json jwk</param>
        /// <returns>.net ECDsa</returns>
        public static ECDsa ConvertJwkToECDsa(string jwkJson)
        {
            // Parse JWK JSON
            var jwk = JsonSerializer.Deserialize<Jwk>(jwkJson);

            // Create ECDsa object from JWK parameters
            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Base64UrlDecode(jwk.x),
                    Y = Base64UrlDecode(jwk.y)
                }
            };

            ECDsa ecdsa = ECDsa.Create(parameters);
            return ecdsa;
        }


        private static byte[] Base64UrlDecode(string base64Url)
        {
            var padded = base64Url.PadRight(base64Url.Length + (4 - base64Url.Length % 4) % 4, '=');
            return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }


        /// <summary>
        /// Converts and ECDsa to a JWK per https://openid.net/specs/draft-jones-json-web-key-03.html
        /// </summary>
        /// <param name="ecdsa"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static Jwk ConvertECDsaToJwk(ECDsa ecdsa, string kid)
        {
            var parameters = ecdsa.ExportParameters(false);

            Jwk kkk = new Jwk();
            kkk.kty = "EC";
            kkk.crv = "P-256";
            kkk.y = Base64UrlEncode(parameters.Q.Y);
            kkk.x = Base64UrlEncode(parameters.Q.X);
            //kkk.d = Base64UrlEncode(parameters.D); //this is the private key
            kkk.kid = kid;

            return kkk;
        }


    }

    /// <summary>
    /// a JWL per https://openid.net/specs/draft-jones-json-web-key-03.html
    /// </summary>
    public class Jwk
    {
        public string kty { get; set; }
        public string crv { get; set; }
        public string x { get; set; }
        public string y { get; set; }
        public string kid { get; set; }
    }
}
