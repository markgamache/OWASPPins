from jwking import jwking, PinConfig, PinPayload, JWKx
from jws import jws
import cert
import time
import json
import os
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509.oid import ExtensionOID
from enum import Enum
import json
from json import JSONEncoder
from mock import Mock
from datetime import datetime, timedelta
import base64


class CustomEncoder(JSONEncoder):
        def default(self, o):
            return o.__dict__



if __name__ == "__main__":
    
    
    #get cert test cert files.
    certFiles = os.listdir("../testcerts/")
    realCerts = list()
    dnsSans = list()

    for file in certFiles:
        f = open("../testcerts/" + file, mode="rb")
        data = f.read()
        thisCert  = cert.cert.load_pem_cert(data)
        realCerts.append(thisCert)
       
        ext = thisCert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
        for san in sans:
            dnsSans.append(san)

        f.close()

    dnsSans = set(dnsSans)
    dnsSans = list(dnsSans)
    #create test certs
    #fooCertRSA = cert.Cert.create_self_signed_certificate("foo.com", "RSA")
    #fooCertEC = cert.Cert.create_self_signed_certificate("foo.com", "EC")

    #exampleCertRSA = cert.Cert.create_self_signed_certificate("example.com", "RSA")
    #exampleCertRSA = cert.Cert.create_self_signed_certificate("example.com", "RSA")


    #create JWKs for signing pinsets to create the config URL JSON
    sss = jwking()
    jwkS1 =  JWKx(sss) 

    sssB = jwking()
    jwkS1B = JWKx(sssB) 

    

    pc = PinConfig("https://place.foo.com/pinset.jwk", [ jwkS1, jwkS1B  ], str(int(time.time())), dnsSans)
    
    print(json.dumps(pc, allow_nan=True, indent=4, cls=CustomEncoder))


    #this is a list of PinPayload s
    the_pins = list()
    for certX in dnsSans:
         tp = the_pins where dnsSans is


    spki1 = cert.Cert.get_subject_public_key_info(fooCertRSA[1])
    sss =  cert.Cert.GenerateHPKPHeader(spki1)
    
    print(sss)

    key = jwking.GenerateKey()
    privKeyAsPem = jwking.ConvertJwkToPEM(key, True)
    pubKeyAsPem = jwking.ConvertJwkToPEM(key, False)
    print(jwking.ConvertJwkToPEM(key, False))

    jsonKey = jwking.ConvertJwkToJson(key, False)
    print(jsonKey)
    reKey = jwking.ImportJwkFromJson(jsonKey)

    theJws = jws()
    theSweetJWS = jws.CreateJws(theJws, "ee", privKeyAsPem)

    jws.VerifyJws(theJws, theSweetJWS, pubKeyAsPem) 

    print("")

