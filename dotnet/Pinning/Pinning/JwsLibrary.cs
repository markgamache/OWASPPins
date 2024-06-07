using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;


namespace Pinning
{
    public class JwsLibrary
    {
        /// <summary>
        /// This takes the ECDsa and uses it to create a JWS
        /// </summary>
        /// <param name="payload">This is just the JSON payload. The header is added by this method and locked to RS256</param>
        /// <param name="privateKey">ECDsa where the private key is present</param>
        /// <returns>the JWS</returns>
        public static string CreateJws(string payload, ECDsa privateKey)
        {
            // Create the header. A more robust implementation would look at key size and create the header.
            var header = new { alg = "ES256", typ = "JSON" };

            // Serialize header and payload to JSON
            var headerJson = JsonSerializer.SerializeToUtf8Bytes(header, new JsonSerializerOptions { WriteIndented = false, Converters = { new JsonStringEnumConverter() }, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            var payloadJson = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions { WriteIndented = false, Converters = { new JsonStringEnumConverter() }, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

            // Base64Url encode the header and payload
            var encodedHeader = Base64UrlEncode(headerJson);
            var encodedPayload = Base64UrlEncode(payloadJson);

            // Combine encoded header and payload with a dot
            var headerPayload = $"{encodedHeader}.{encodedPayload}";

            // Sign the header and payload
            var signature = SignJws(privateKey, headerPayload);

            // Combine encoded header, payload, and signature with dots
            return $"{headerPayload}.{signature}";
        }

        public static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public static byte[] Base64UrlDecode(string base64Url)
        {
            var padded = base64Url.PadRight(base64Url.Length + (4 - base64Url.Length % 4) % 4, '=');
            return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        }


        /// <summary>
        /// Signs the JWK header and payload
        /// </summary>
        /// <param name="ecdsa"></param>
        /// <param name="headerAndPayload"></param>
        /// <returns></returns>
        private static string SignJws(ECDsa ecdsa, string headerAndPayload)
        {
            byte[] payloadBytes = Encoding.UTF8.GetBytes(headerAndPayload);
            byte[] signature = ecdsa.SignData(payloadBytes, HashAlgorithmName.SHA256);

            string encodedSignature = Base64UrlEncode(signature);

            return encodedSignature;
        }


        /// <summary>
        /// Splits out the JWS parts and verifies the data, per https://openid.net/specs/draft-jones-json-web-signature-04.html 
        /// </summary>
        /// <param name="ecdsa"></param>
        /// <param name="jws"></param>
        /// <returns></returns>
        public static bool VerifyJws(ECDsa ecdsa, string jws)
        {
            string[] parts = jws.Split('.');

            if (parts.Length != 3)
                return false;

            //one should look at parts[0] to make sure the header matches the crypto

            string payload = $"{parts[0]}.{parts[1]}";
            string encodedSignature = parts[2];

            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            byte[] signatureBytes = Base64UrlDecode(encodedSignature);

            return ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256);
        }

    }

    public class PinPayload
    {
        public string domain { get; set; }
        public List<string> key_pinsL = new List<string>();
        public string last_updated { get; private set; }

        public string[] key_pins { get { return key_pinsL.ToArray(); }  }

        public void SetUpdateDate(DateTime when)
        {
            long realEpoch = ((DateTimeOffset)when).ToUnixTimeSeconds();
            last_updated = realEpoch.ToString("d");

        }
    }


    public class PinConfig
    {
        public string pinset_url { get; set; }

        public Jwk[] pinset_keys { get; set; }

        public string[] applies_to { get; set; }

        public string last_updated { get; private set; }

        public void SetUpdateDate(DateTime when)
        {
            long realEpoch = ((DateTimeOffset)when).ToUnixTimeSeconds();
            last_updated = realEpoch.ToString("d");

        }

    }
}
