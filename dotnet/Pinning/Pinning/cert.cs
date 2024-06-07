using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Runtime.InteropServices;
using System.Numerics;
using System.Collections;
using System.Net.NetworkInformation;




namespace Pinning
{
    public class cert
    {
        const string beginMarkerCert = "-----BEGIN CERTIFICATE-----";
        const string endMarkerCert = "-----END CERTIFICATE-----";

        public static X509Certificate2 ImportCertifcateFromFile(string file)
        {

            X509Certificate2 cert = new X509Certificate2(file);

            return cert;
        }

        public static X509Certificate2 ImportCertifcateFromPemStr(string PEM)
        {
            byte[] pemByets = GetCertBytesFromPem(PEM);

            X509Certificate2 cert = new X509Certificate2(pemByets);

            return cert;
        }


        public static byte[] GetCertBytesFromPem(string pemData)
        {


            int startIndex = pemData.IndexOf(beginMarkerCert, StringComparison.Ordinal);
            if (startIndex < 0)
            {
                throw new ArgumentException("Invalid PEM format: BEGIN marker not found.");
            }

            int endIndex = pemData.IndexOf(endMarkerCert, startIndex + beginMarkerCert.Length, StringComparison.Ordinal);
            if (endIndex < 0)
            {
                throw new ArgumentException("Invalid PEM format: END marker not found.");
            }

            string base64 = pemData.Substring(startIndex + beginMarkerCert.Length, endIndex - (startIndex + beginMarkerCert.Length));
            base64 = base64.Replace("\r", string.Empty).Replace("\n", string.Empty);

            return Convert.FromBase64String(base64);
        }


        public static X509Certificate2 GenerateSelfSignedCertificateRsa2048(string dnsName)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(
                    "CN=" + dnsName,
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                SubjectAlternativeNameBuilder sans = new SubjectAlternativeNameBuilder();
                sans.AddDnsName(dnsName);
                var sansEx = sans.Build();
                request.CertificateExtensions.Add(sansEx);

                DateTime notBefore = DateTime.UtcNow;
                DateTime notAfter = notBefore.AddYears(1);

                var certificate = request.CreateSelfSigned(notBefore, notAfter);
                return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
            }
        }

        public static X509Certificate2 GenerateSelfSignedCertificateNistP256(string dnsName)
        {
            using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var request = new CertificateRequest(
                    "CN=" + dnsName,
                    ecdsa,
                    HashAlgorithmName.SHA256);

                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                SubjectAlternativeNameBuilder sans = new SubjectAlternativeNameBuilder();
                sans.AddDnsName(dnsName);
                var sansEx = sans.Build();
                request.CertificateExtensions.Add(sansEx);


                DateTime notBefore = DateTime.UtcNow;
                DateTime notAfter = notBefore.AddYears(1);

                var certificate = request.CreateSelfSigned(notBefore, notAfter);
                return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
            }
        }


        /// <summary>
        /// Genearic export of RSA and ECC keys as well as Certs to PEM
        /// </summary>
        /// <param name="obj">An object that can be pem'd: ECDsa, RSA, X509Certificate2</param>
        /// <returns>PEM string</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static string ExportToPem(object obj)
        {
            if (obj is ECDsa ecdsa)
            {
                return ExportECDSAKeyToPem(ecdsa);
            }
            else if (obj is RSA rsa)
            {
                return ExportRSAKeyToPem(rsa);
            }
            else if (obj is X509Certificate2 certificate)
            {
                return ExportCertificateToPem(certificate);
            }

            throw new NotSupportedException("Unsupported object type for PEM export.");
        }


        //specific exports keys and certs to strings 

        private static string ExportECDSAKeyToPem(ECDsa ecdsa)
        {
            StringWriter sw = new StringWriter();
            sw.WriteLine("-----BEGIN PRIVATE KEY-----");

            var parameters = ecdsa.ExportParameters(true);
            sw.WriteLine(Convert.ToBase64String(parameters.D, Base64FormattingOptions.InsertLineBreaks));
            sw.WriteLine("-----END PRIVATE KEY-----");
            return sw.ToString();
        }


        private static string ExportRSAKeyToPem(RSA rsa)
        {
            StringWriter sw = new StringWriter();
            sw.WriteLine("-----BEGIN PRIVATE KEY-----");

            var parameters = rsa.ExportParameters(true);
            sw.WriteLine(Convert.ToBase64String(parameters.Modulus, Base64FormattingOptions.InsertLineBreaks));
            sw.WriteLine(Convert.ToBase64String(parameters.Exponent, Base64FormattingOptions.InsertLineBreaks));
            sw.WriteLine(Convert.ToBase64String(parameters.D, Base64FormattingOptions.InsertLineBreaks));

            sw.WriteLine("-----END PRIVATE KEY-----");
            return sw.ToString();
        }


        private static string ExportCertificateToPem(X509Certificate2 certificate)
        {

            StringWriter sw = new StringWriter();
            sw.WriteLine(beginMarkerCert);
            sw.WriteLine(FormatBase64PEM(Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.None), 64));
            sw.WriteLine(endMarkerCert);
            return sw.ToString();
        }

        //while PEM does not HAVE to be 64 columns, it looks better and is most accpeted
        static string FormatBase64PEM(string base64String, int lineLength)
        {
            StringBuilder formattedBase64 = new StringBuilder();

            for (int i = 0; i < base64String.Length; i += lineLength)
            {
                int length = Math.Min(lineLength, base64String.Length - i);
                formattedBase64.Append(base64String.Substring(i, length));
                formattedBase64.AppendLine();
            }

            return formattedBase64.ToString().TrimEnd();
        }


        /// <summary>
        /// Takes in an X509Certificate2 and extracts the Subject Public Key Info per https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7
        /// and creates a sha256 hash of it
        /// </summary>
        /// <param name="certificate">X509Certificate2</param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public static string GenerateHPKPHeader(X509Certificate2 certificate)
        {
            HashAlgorithmName algorithm = HashAlgorithmName.SHA256;

            byte[] spki = parseX509SubPubKeyInfo(certificate); ;

            // Hash the Base64-encoded SPKI
            byte[] hash;
            using (var hasher = HashAlgorithm.Create(algorithm.Name))
            {
                if (hasher == null)
                {
                    throw new NotSupportedException($"Hash algorithm {algorithm.Name} is not supported.");
                }

                hash = hasher.ComputeHash(spki);
            }

            // Base64 encode the hash
            string base64Hash = Convert.ToBase64String(hash);

            // Construct the HPKP header
            string hpkpHeader = $"pin-{algorithm.Name.ToLower()}={base64Hash}";
                        
            return hpkpHeader;
        }



        /// <summary>
        /// This pulls the Subject public key info from the cert ASN1.
        /// It is ugly becuse asn1 is no fun.
        /// 
        /// </summary>
        /// <param name="bytes">Certificate as byte[]</param>
        /// <returns>SPKI as a byte array</returns>
        /// <exception cref="Exception"></exception>
        public static byte[] parseX509SubPubKeyInfo(X509Certificate2 certificate)
        {
            byte[] bytes = certificate.GetRawCertData();

            //top SEQ
            if (bytes[0] != 0x30 && bytes[1] != 0x82 )
            {   //even the smallest cert has a lenght of 2 btyes
                throw new Exception("not a cert");

            }

            //these to used to get a SEQ LEN, which can be one or two bytes 
            int sizeOfSize = 2;
            int destIndex = 0;

            int mainSeqLen = bytes[5];

            int cursorPos = 4;

            
            if (mainSeqLen == 0x82)
            {
                //long form means the lenthgt is 2 bytes
                sizeOfSize = 4;
            }
            else if (mainSeqLen == 0x81)
            {
                //this means short from and >126.  we lose a byte callng out short form, but the lenght is single byte still
                sizeOfSize = 3;
            }
            else
            {
                //this means the nextInSeq is actual a single byte representing the lenght 
                sizeOfSize = 2;
            }


            //skip x509 version
            cursorPos = cursorPos +  sizeOfSize;

            if (bytes[cursorPos] != 0xa0)
            {

                throw new Exception("not a cert");

            }

            int verLen = bytes[cursorPos + 1];


            //skip serial
            cursorPos = cursorPos + verLen + 2;
            if (bytes[cursorPos] != 0x02)
            {
                throw new Exception("not a cert");
            }

            int serialLen = bytes[cursorPos + 1];

            if (serialLen == 0x82)
            {
                //long form means the lenthgt is 2 bytes
                sizeOfSize = 4;
                serialLen = BytesToInt(bytes[cursorPos + 2], bytes[cursorPos + 3]);
            }
            else if (serialLen == 0x81)
            {
                //this means short from and >126.  we lose a byte callng out short form, but the lenght is single byte still
                sizeOfSize = 2;
                serialLen = bytes[cursorPos + 1];
            }
            else
            {
                //this means the nextInSeq is actual a single byte representing the lenght 
                sizeOfSize = 1;
                //serialLen = serialLen;
            }

            cursorPos = cursorPos + sizeOfSize + serialLen + 1;

            if (bytes[cursorPos] != 0x30)
            {
                throw new Exception("not a cert");

            }

            cursorPos++;

            //skip sig type
            int sigTypeLen = bytes[cursorPos];
            cursorPos = cursorPos + sigTypeLen + 1;

            if (bytes[cursorPos] != 0x30)
            {
                throw new Exception("not a cert");
            }

            cursorPos++;

            //skip issuer 

            int issuerLen = bytes[cursorPos];


            if (issuerLen == 0x82)
            {
                //long form means the lenthgt is 2 bytes
                sizeOfSize = 4;
                issuerLen = BytesToInt(bytes[cursorPos + 2], bytes[cursorPos + 3]);
            }
            else if (issuerLen == 0x81)
            {
                //this means short from and >126.  we lose a byte callng out short form, but the lenght is single byte still
                sizeOfSize = 2;
                issuerLen = bytes[cursorPos + 1];
            }
            else
            {
                //this means the nextInSeq is actual a single byte representing the lenght 
                sizeOfSize = 1;
                issuerLen = bytes[cursorPos];
            }

            cursorPos = cursorPos + (int) issuerLen + sizeOfSize;

            if (bytes[cursorPos] != 0x30)
            {
                throw new Exception("not a cert");
            }

            //time validity
            cursorPos++;
            int notBeforeLen = bytes[cursorPos];

            cursorPos = cursorPos + notBeforeLen + 1;

            if (bytes[cursorPos] != 0x30)
            {
                throw new Exception("not a cert");
            }


            //subject
            cursorPos++;
            int subjectLen = bytes[cursorPos];

            if (subjectLen == 0x82)
            {
                //long form means the lenthgt is 2 bytes
                sizeOfSize = 4;
                subjectLen = BytesToInt(bytes[cursorPos + 2], bytes[cursorPos + 3]);
            }
            else if (subjectLen == 0x81)
            {
                //this means short from and >126.  we lose a byte callng out short form, but the lenght is single byte still
                sizeOfSize = 2;
                subjectLen = bytes[cursorPos + 1];
            }
            else
            {
                //this means the nextInSeq is actual a single byte representing the lenght 
                sizeOfSize = 1;
                subjectLen = bytes[cursorPos];
            }

            cursorPos = cursorPos + (int)subjectLen + sizeOfSize;


            //cursorPos += subjectLen + 1;
            /* todo see if this fixes mid long sugject
            if (bytes[cursorPos] != 0x30)
            {
                throw new Exception("not a cert");
            }

            */

            //at subject key!  We will need to extract the key teype and key info. 
            int nextInSeq = bytes[cursorPos + 1];

            int subjectKeyLen = 0;

            if (nextInSeq == 0x82)
            {
                //long form means the lenthgt is 2 bytes
                sizeOfSize = 4;
                subjectKeyLen = BytesToInt(bytes[cursorPos + 2], bytes[cursorPos + 3]);
            }
            else if (nextInSeq == 0x81)
            {
                //this means short from and >126.  we lose a byte callng out short form, but the lenght is single byte still
                sizeOfSize = 2;
                subjectKeyLen = bytes[cursorPos + 2];
            }
            else
            {
                //this means the nextInSeq is actual a single byte representing the lenght 
                sizeOfSize = 2;
                subjectKeyLen = bytes[cursorPos + 1];
            }


            byte[] subjectKeyInfo = new byte[subjectKeyLen + sizeOfSize];


            if (nextInSeq == 0x82)
            {
                subjectKeyInfo[0] = bytes[cursorPos];
                subjectKeyInfo[1] = 0x82;
                subjectKeyInfo[2] = bytes[cursorPos + 2];
                subjectKeyInfo[3] = bytes[cursorPos + 3];
                destIndex = 4;
            }
            else if (nextInSeq == 0x81)
            {
                subjectKeyInfo[0] = bytes[cursorPos];
                subjectKeyInfo[1] = 0x81;
                subjectKeyInfo[2] = bytes[cursorPos + 2];
                destIndex = 3;

            }
            else
            {
                subjectKeyInfo[0] = bytes[cursorPos];
                subjectKeyInfo[1] = (byte)subjectKeyLen;
                destIndex = 2;
            }



            Array.Copy(bytes, (cursorPos + sizeOfSize), subjectKeyInfo, destIndex, subjectKeyLen);

            return subjectKeyInfo;



        }

        /// <summary>
        /// Takes a byte[] that is an integer of 2 bytes and make it an int.
        /// </summary>
        /// <param name="byte1">b1</param>
        /// <param name="byte2">b2</param>
        /// <returns>the int</returns>
        static int BytesToInt(byte byte1, byte byte2)
        {
            string xx  = (BitConverter.ToString(new byte[] { byte1, byte2 })).Replace("-", ""); 

            long ss = long.Parse(xx, System.Globalization.NumberStyles.AllowHexSpecifier);

            return (int) ss;

        }

    
    }


}
