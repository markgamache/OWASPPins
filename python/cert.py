import os
import sys
import getopt
from pathlib import Path
import shutil
import subprocess
import datetime
import time
import urllib.request
import requests
import OpenSSL
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
#from dateutil.parser import parse
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
from mock import Mock
from datetime import datetime, timedelta
import base64


class cert:
    #def __init__(self):
    #    pass

    def create_self_signed_certificate(cn: str, keyType: str) -> tuple:
        # Generate a private key
        
        if keyType == "RSA":

        
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        elif keyType == "EC":

            curve = ec.SECP521R1()

            private_key = ec.generate_private_key(curve, backend=default_backend())
        else:
            raise ValueError("keyType must be EC or RSA")
            

        # Create a subject for the certificate
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"{}".format(cn)),
        ])

        # Create a certificate
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(
            private_key, hashes.SHA256(), default_backend()
        )

        # Serialize private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize certificate to PEM format
        certificate_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

        return private_key_pem, certificate_pem
    
    def get_subject_public_key_info(certificatePem : str ) -> bytes:

        certificate = x509.load_pem_x509_certificate(certificatePem, backend=default_backend())
        spki = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return spki
    
    def GenerateHPKPHeader(spkiBytes: bytes) -> str:
        sha256_ctx = hashes.Hash(hashes.SHA256(), backend=default_backend())
        sha256_ctx.update(spkiBytes)
        hash_result = sha256_ctx.finalize()

        hashStr = (base64.b64encode(hash_result)).decode()

        return "pin-sha256={}".format(hashStr)

    def load_pem_cert(certificatePem : str ) -> x509.Certificate:
        certificate = x509.load_pem_x509_certificate(certificatePem, backend=default_backend())
        return certificate
    




 


    
