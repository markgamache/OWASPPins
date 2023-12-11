using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;


namespace Pinning
{
    public class JwsLibrary
    {
        public static string CreateJws(string payload, string privateKey)
        {
            // Create the header
            var header = new { alg = "RS256", typ = "JWT" };

            // Serialize header and payload to JSON
            var headerJson = JsonSerializer.SerializeToUtf8Bytes(header);
            var payloadJson = JsonSerializer.SerializeToUtf8Bytes(payload);

            // Base64Url encode the header and payload
            var encodedHeader = Base64UrlEncode(headerJson);
            var encodedPayload = Base64UrlEncode(payloadJson);

            // Combine encoded header and payload with a dot
            var headerPayload = $"{encodedHeader}.{encodedPayload}";

            // Sign the header and payload
            var signature = SignData(headerPayload, privateKey);

            // Base64Url encode the signature
            var encodedSignature = Base64UrlEncode(signature);

            // Combine encoded header, payload, and signature with dots
            return $"{headerPayload}.{encodedSignature}";
        }

        public static bool VerifyJws(string jws, string publicKey)
        {
            // Split the JWS into header, payload, and signature
            var parts = jws.Split('.');
            if (parts.Length != 3)
            {
                return false; // Invalid JWS format
            }

            var encodedHeader = parts[0];
            var encodedPayload = parts[1];
            var encodedSignature = parts[2];

            // Decode the header, payload, and signature
            var headerJson = Base64UrlDecode(encodedHeader);
            var payloadJson = Base64UrlDecode(encodedPayload);
            var signature = Base64UrlDecode(encodedSignature);

            // Verify the signature
            var headerPayload = $"{encodedHeader}.{encodedPayload}";
            return VerifyData(headerPayload, signature, publicKey);
        }

        private static byte[] SignData(string data, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                return rsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private static bool VerifyData(string data, byte[] signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);
                return rsa.VerifyData(Encoding.UTF8.GetBytes(data), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static byte[] Base64UrlDecode(string base64Url)
        {
            var padded = base64Url.PadRight(base64Url.Length + (4 - base64Url.Length % 4) % 4, '=');
            return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        }



        public static string SignJws(ECDsa ecdsa, string payload)
        {
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            byte[] signature = ecdsa.SignData(payloadBytes, HashAlgorithmName.SHA256);

            string encodedSignature = Base64UrlEncode(signature);

            return $"{payload}.{encodedSignature}";
        }

        public static bool VerifyJws(ECDsa ecdsa, string jws)
        {
            string[] parts = jws.Split('.');

            if (parts.Length != 2)
                return false;

            string payload = parts[0];
            string encodedSignature = parts[1];

            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            byte[] signatureBytes = Base64UrlDecode(encodedSignature);

            return ecdsa.VerifyData(payloadBytes, signatureBytes, HashAlgorithmName.SHA256);
        }




    }
}
