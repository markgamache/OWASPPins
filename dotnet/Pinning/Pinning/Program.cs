using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Text.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;



namespace Pinning
{
    internal class Program
    {
        static void Main(string[] args)
        {


            //create test certs to pin
            X509Certificate2 fooCertA = cert.GenerateSelfSignedCertificateRsa2048("foo.com");
            Console.WriteLine("foo.com RSA");
            Console.WriteLine(cert.ExportToPem(fooCertA));

            X509Certificate2 exampleCertA = cert.GenerateSelfSignedCertificateRsa2048("example.com");
            Console.WriteLine("example.com RSA");
            Console.WriteLine(cert.ExportToPem(exampleCertA));

            X509Certificate2 fooCertB = cert.GenerateSelfSignedCertificateNistP256("foo.com");
            Console.WriteLine("foo.com ECC");
            Console.WriteLine(cert.ExportToPem(fooCertB));

            X509Certificate2 exampleCertB = cert.GenerateSelfSignedCertificateNistP256("example.com");
            Console.WriteLine("example.com ECC");
            Console.WriteLine(cert.ExportToPem(exampleCertB));



            //Create keys for signing pinsets and create the Config URL JSON
            ECDsa jwk1 = JwkLibrary.CreateNewECDSA();
            Jwk jwkS1 = JwkLibrary.ConvertECDsaToJwk(jwk1, "key1");

            ECDsa jwk2 = JwkLibrary.CreateNewECDSA();
            Jwk jwkS2 = JwkLibrary.ConvertECDsaToJwk(jwk2, "key2");

            PinConfig pinConf = new PinConfig();
            pinConf.SetUpdateDate(DateTime.Now);
            pinConf.applies_to = new string[] { "foo.com", "example.com" };
            pinConf.pinset_keys = new Jwk[] { jwkS1, jwkS2 };
            pinConf.pinset_url = "https://place.foo.com/pinset.jwk";

            string jsonOfConfig = JsonSerializer.Serialize(pinConf, new JsonSerializerOptions { WriteIndented = true });

            Console.WriteLine(jsonOfConfig);


            //create the signed pinset
            PinPayload[] thePins = new PinPayload[2];
            PinPayload ppFoo = new PinPayload();
            PinPayload ppExample = new PinPayload();
            thePins[0] = ppFoo;
            thePins[1] = ppExample;

            ppFoo.SetUpdateDate(DateTime.Now);
            ppFoo.domain = "foo.com";
            ppFoo.key_pins = new string[] { cert.GenerateHPKPHeader(fooCertA), cert.GenerateHPKPHeader(fooCertB) };


            ppExample.SetUpdateDate(DateTime.Now);
            ppExample.domain = "example.com";
            ppExample.key_pins = new string[] { cert.GenerateHPKPHeader(exampleCertA), cert.GenerateHPKPHeader(exampleCertB) };

            //string unsignedPinset = JsonSerializer.Serialize(thePins);
            string unsignedPinset = JsonSerializer.Serialize(thePins, new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() }, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            

            //take the pinsent and sign it with a JWK
            string finalJWS1 = JwsLibrary.CreateJws(unsignedPinset, jwk1);

            //check signed set against config data

            bool passes = verifySignePinset(finalJWS1, jsonOfConfig);

            if (passes)
            {
                string[] parts = finalJWS1.Split('.');

                if (parts.Length != 3)
                    throw new Exception("Your JWS is broken");

                string header = Encoding.UTF8.GetString(JwsLibrary.Base64UrlDecode(parts[0]));
                string payload = Encoding.UTF8.GetString(JwsLibrary.Base64UrlDecode(parts[1]));
                payload = fixBadlyEscapedJson(payload);
                Console.WriteLine(header + "\n");
                Console.WriteLine(payload + "\n");
            }
            else
            {
                Console.WriteLine("This failed and should not have!");
            }


            //test break the signing 
            ECDsa jwk3 = JwkLibrary.CreateNewECDSA();
            string finalJWS2 = JwsLibrary.CreateJws(unsignedPinset, jwk3);

            bool passes2 = verifySignePinset(finalJWS2, jsonOfConfig);


            if (passes2)
            {
                Console.WriteLine("Intended Fail did not fail. Freak out!");
                string[] parts = finalJWS2.Split('.');

                if (parts.Length != 3)
                    throw new Exception("Your JWS is broken");

                string header = Encoding.UTF8.GetString(JwsLibrary.Base64UrlDecode(parts[0]));
                string payload = Encoding.UTF8.GetString(JwsLibrary.Base64UrlDecode(parts[1]));
                Console.WriteLine(header + "\n");
                Console.WriteLine(payload + "\n");

            }
            else
            {
                Console.WriteLine("Intended Fail worked");
            }


            Console.WriteLine("");
        }


        /// <summary>
        /// Turn Json of keys back into PinPayload[]
        /// </summary>
        /// <param name="jsonOFKeys">json string of the pin payload</param>
        /// <returns>PinPayload[] containing keys</returns>
        static PinPayload[] openKeys(string jsonOFKeys)
        {

            string jsonFixed = fixBadlyEscapedJson(jsonOFKeys);
            PinPayload[] pins = JsonSerializer.Deserialize<PinPayload[]>(jsonFixed);
            return pins;

        }


        //.net JSON is not always fun
        static string fixBadlyEscapedJson(string uglyJson)
        {
            string jsonFixed = uglyJson.Replace("\\\"", "\"");
            jsonFixed = jsonFixed.Replace("\\r", "\r");
            jsonFixed = jsonFixed.Replace("\\n", "\n");
            jsonFixed = jsonFixed.Substring(1);
            jsonFixed = jsonFixed.Substring(0, jsonFixed.Length - 1);

            return jsonFixed;
        }


        /// <summary>
        /// Try all key from the config JSON to see if any signed the signed Pinset
        /// </summary>
        /// <param name="pinSetJwt"></param>
        /// <param name="pinConfigJson"></param>
        /// <returns></returns>
        static bool verifySignePinset(string pinSetJwt, string pinConfigJson)
        {
            PinConfig pConf = JsonSerializer.Deserialize<PinConfig>(pinConfigJson);

            foreach (Jwk k in pConf.pinset_keys)
            {
                //turn the JWK back into ecdsa


                ECDsa eccK = JwkLibrary.ConvertJwkToECDsa(JsonSerializer.Serialize(k));

                bool verify = JwsLibrary.VerifyJws(eccK, pinSetJwt);
                if (verify)
                {
                    return true;
                }

            }

            return false;
        }

    }
}
