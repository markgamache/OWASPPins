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



        public JwkLibrary()
        {
            ECDsa xx = CreateNewECDSA();
            xx.GenerateKey(ECCurve.NamedCurves.nistP256);

            

            string yy = ConvertECDsaToJwk(xx, "mykid");

            ECDsa reHydrated = ConvertJwkToECDsa(yy);

            

            string sig = JwsLibrary.SignJws(xx, "words");



            bool bbb = JwsLibrary.VerifyJws(reHydrated, sig);

            Console.WriteLine("");

        }


        static ECDsa CreateNewECDSA()
        {

            ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            return ecdsa;
        }


        static ECDsa ConvertJwkToECDsa(string jwkJson)
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

        static bool VerifySignature(ECDsa ecdsa, string message, byte[] signature)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }

        static byte[] Base64UrlDecode(string base64Url)
        {
            var padded = base64Url.PadRight(base64Url.Length + (4 - base64Url.Length % 4) % 4, '=');
            return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        }



        static string ConvertECDsaToJwk(ECDsa ecdsa)
        {
            var parameters = ecdsa.ExportParameters(true);

            // Create JWK object
            var jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncode(parameters.Q.X),
                y = Base64UrlEncode(parameters.Q.Y),
                d = Base64UrlEncode(parameters.D)
            };

            string jsonOfJWK = JsonSerializer.Serialize(jwk, new JsonSerializerOptions { WriteIndented = true });

            return jsonOfJWK;
        }

        static string ConvertECDsaToJwk(ECDsa ecdsa, string kid)
        {
            var parameters = ecdsa.ExportParameters(true);

            // Create JWK object
            var jwk = new
            {
                kty = "EC",
                crv = "P-256",
                x = Base64UrlEncode(parameters.Q.X),
                y = Base64UrlEncode(parameters.Q.Y),
                d = Base64UrlEncode(parameters.D),
                kid = kid
            };

            string jsonOfJWK = JsonSerializer.Serialize(jwk, new JsonSerializerOptions { WriteIndented = true });

            return jsonOfJWK;
        }

        static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }


        static ECDsa ImportECDsaFromPemFile(string pemFilePath)
        {
            try
            {
                string pemContents = File.ReadAllText(pemFilePath);

                // Remove PEM header and footer
                string base64PrivateKey = RemovePemHeaderAndFooter(pemContents);

                // Decode base64 string to byte array
                byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey);

                // Import the private key using a workaround (not recommended for production)
                ECDsa ecdsa = ECDsa.Create();
                ecdsa.ImportParameters(ReadECPrivateKey(privateKeyBytes));

                return ecdsa;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error importing ECDsa key: {ex.Message}");
            }

            return null;
        }

        static ECParameters ReadECPrivateKey(byte[] privateKeyBytes)
        {
            // Parse the ASN.1 DER encoded private key
            int index = 0;

            // Skip the ASN.1 version byte
            if (privateKeyBytes[index++] != 0x30)
                throw new InvalidOperationException("Invalid ASN.1 DER encoding.");

            // Read the length of the sequence
            int length = privateKeyBytes[index++];
            if ((length & 0x80) == 0x80)
            {
                int additionalBytes = length & 0x7F;
                length = 0;
                while (additionalBytes-- > 0)
                    length = (length << 8) | privateKeyBytes[index++];
            }

            // Skip the ASN.1 object identifier for the EC private key
            if (privateKeyBytes[index++] != 0x06 || privateKeyBytes[index++] != 0x07 ||
                privateKeyBytes[index++] != 0x2A || privateKeyBytes[index++] != 0x86 ||
                privateKeyBytes[index++] != 0x48 || privateKeyBytes[index++] != 0xCE ||
                privateKeyBytes[index++] != 0x3D || privateKeyBytes[index++] != 0x04 ||
                privateKeyBytes[index++] != 0x03 || privateKeyBytes[index++] != 0x02)
                throw new InvalidOperationException("Invalid ASN.1 DER encoding.");

            // Skip the ASN.1 octet string tag
            if (privateKeyBytes[index++] != 0x04)
                throw new InvalidOperationException("Invalid ASN.1 DER encoding.");

            // Read the length of the octet string
            int keyLength = privateKeyBytes[index++];
            if ((keyLength & 0x80) == 0x80)
            {
                int additionalBytes = keyLength & 0x7F;
                keyLength = 0;
                while (additionalBytes-- > 0)
                    keyLength = (keyLength << 8) | privateKeyBytes[index++];
            }

            // Copy the key bytes
            byte[] keyBytes = new byte[keyLength];
            Buffer.BlockCopy(privateKeyBytes, index, keyBytes, 0, keyLength);

            // Create ECParameters object
            return new ECParameters
            {
                D = keyBytes,
                Curve = ECCurve.NamedCurves.nistP256
            };
        }

        static string RemovePemHeaderAndFooter(string pemContents)
        {
            const string pemHeader = "-----BEGIN PRIVATE KEY-----";
            const string pemFooter = "-----END PRIVATE KEY-----";

            int startIdx = pemContents.IndexOf(pemHeader, StringComparison.Ordinal);
            int endIdx = pemContents.IndexOf(pemFooter, StringComparison.Ordinal);

            if (startIdx >= 0 && endIdx >= 0)
            {
                startIdx += pemHeader.Length;
                return pemContents.Substring(startIdx, endIdx - startIdx).Replace("\n", "").Replace("\r", "");
            }

            return null;
        }






        static string ExportECDsaPublicKeyToPem(ECDsa ecdsa)
        {
            // Get the public key parameters
            ECParameters parameters = ecdsa.ExportParameters(false);

            // Export the public key to PEM format
            return ExportKeyToPem("PUBLIC KEY", parameters);
        }

        static string ExportECDsaPrivateKeyToPem(ECDsa ecdsa)
        {
            // Get the private key parameters
            ECParameters parameters = ecdsa.ExportParameters(true);

            // Export the private key to PEM format
            return ExportKeyToPem("PRIVATE KEY", parameters);
        }

        static string ExportKeyToPem(string keyType, ECParameters parameters)
        {
            // Convert key parameters to ASN.1 DER encoding
            byte[] derBytes = EncodeECPublicKey(parameters);

            // Convert to base64 and format as PEM
            string base64 = Convert.ToBase64String(derBytes);
            return $"-----BEGIN {keyType}-----\n{FormatPem(base64)}-----END {keyType}-----\n";
        }

        static byte[] EncodeECPublicKey(ECParameters parameters)
        {
            byte[] prefix = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };

            byte[] xBytes = parameters.Q.X;
            byte[] yBytes = parameters.Q.Y;

            int length = prefix.Length + xBytes.Length + yBytes.Length;

            byte[] result = new byte[length];

            Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
            Buffer.BlockCopy(xBytes, 0, result, prefix.Length, xBytes.Length);
            Buffer.BlockCopy(yBytes, 0, result, prefix.Length + xBytes.Length, yBytes.Length);

            return result;
        }

        static string FormatPem(string base64)
        {
            const int LineLength = 64;
            StringBuilder formatted = new StringBuilder();

            for (int i = 0; i < base64.Length; i += LineLength)
            {
                int lineSize = Math.Min(LineLength, base64.Length - i);
                formatted.Append(base64, i, lineSize);
                formatted.AppendLine();
            }

            return formatted.ToString();
        }

    }



    public class Jwk
    {
        public string kty { get; set; }
        public string crv { get; set; }
        public string x { get; set; }
        public string y { get; set; }
        public string kid { get; set; }
    }
}
