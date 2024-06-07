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
using System.Xml.Linq;



namespace Pinning
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //get and read the test certs
            string[] testCerts = Directory.GetFiles(@"..\..\..\..\..\testcerts");

            X509Certificate3[] testCertsB = new X509Certificate3[testCerts.Length];

            List<string> namesForConfUrl = new List<string>();

            short ind = 0;
            foreach (string testCert in testCerts)
            {
                X509Certificate2 thisCert = new X509Certificate2(testCert);
                string hash = cert.GenerateHPKPHeader(thisCert);
                Console.WriteLine($"{thisCert.Subject} {hash}");
                testCertsB[ind] = new X509Certificate3(thisCert);
                namesForConfUrl.AddRange(testCertsB[ind].dnsSans);
                ind++;

            }



            //Create keys for signing pinsets and create the Config URL JSON
            ECDsa jwk1 = JwkLibrary.CreateNewECDSA();
            Jwk jwkS1 = JwkLibrary.ConvertECDsaToJwk(jwk1, "key1");

            ECDsa jwk2 = JwkLibrary.CreateNewECDSA();
            Jwk jwkS2 = JwkLibrary.ConvertECDsaToJwk(jwk2, "key2");

            PinConfig pinConf = new PinConfig();
            pinConf.SetUpdateDate(DateTime.Now);
            pinConf.applies_to = namesForConfUrl.ToArray();// new string[] { "crt.sh", "community.letsencrypt.org", "letsencrypt.org", "owasp.org" };
            pinConf.pinset_keys = new Jwk[] { jwkS1, jwkS2 };
            pinConf.pinset_url = "https://place.foo.com/pinset.jwk";

            string jsonOfConfig = JsonSerializer.Serialize(pinConf, new JsonSerializerOptions { WriteIndented = true });

            Console.WriteLine("This is the Config JSON. It can't be signed");
            Console.WriteLine(jsonOfConfig);
            Console.WriteLine("");

            //create the signed pinset
            List<PinPayload> thePins = new List<PinPayload>();

            short ppCount = 0;
            foreach (string certX in namesForConfUrl)
            {

                PinPayload pinPayload = thePins.Where(x => x.domain == certX).FirstOrDefault();
                if (pinPayload == null)
                {
                    PinPayload pp = new PinPayload();
                    pp.SetUpdateDate(DateTime.Now);
                    pp.domain = certX;
                    //X509Certificate2 c2 = (X509Certificate2)certX;
                    List<X509Certificate3> certsInPlay = testCertsB.Where(x => x.dnsSans.Contains(certX)).ToList();

                    foreach (X509Certificate3 certY in certsInPlay)
                    {
                        string thisPin = cert.GenerateHPKPHeader(certY.x509Certificate2);
                        if (!pp.key_pinsL.Contains(thisPin))
                        {
                            pp.key_pinsL.Add(thisPin);
                        }
                    }

                    thePins.Add( pp);
                }
                
                ppCount++;
            }


            //string unsignedPinset = JsonSerializer.Serialize(thePins);
            string unsignedPinset = JsonSerializer.Serialize(thePins, new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() }, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

            Console.WriteLine("This is the unsigned Pinset");
            Console.WriteLine(unsignedPinset);
            Console.WriteLine("");



            //take the pinsent and sign it with a JWK
            string finalJWS1 = JwsLibrary.CreateJws(unsignedPinset, jwk1);

            Console.WriteLine("This is the valid JWS of the Pinset");
            Console.WriteLine(finalJWS1);
            Console.WriteLine("");

            //check signed set against config data
            bool passes = verifySignePinset(finalJWS1, jsonOfConfig);

            if (passes)
            {
                Console.WriteLine("The JWS was valid. This is the header and payload");
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

    internal class X509Certificate3
    {
        public string[] dnsSans { get; private set; }
        public X509Certificate2 x509Certificate2 { get; private set; }

        public X509Certificate3(X509Certificate2 certIn)
        {
            x509Certificate2 = certIn;
            List<string> namesForConfUrl = new List<string>();

            foreach (X509Extension extension in certIn.Extensions)
            {
                AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);
                // Subject Alternative Name not guaranteed to be same friendly name across platforms.
                // Using Oid value here.
                if (asnData.Oid.Value == "2.5.29.17")
                {
                    string decodedData = asnData.Format(false);
                    string[] parts = decodedData.Split(',');
                    foreach (string part in parts)
                    {
                        string thisPart = part.Split('=')[1].Trim();
                        namesForConfUrl.Add(thisPart);

                    }
                }
            }

            dnsSans = namesForConfUrl.ToArray();
        }
    }
}
