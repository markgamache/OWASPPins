import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class jws:
    def __init__(self):
        pass

    
    def base64_to_base64url(self, base64_string: str) -> str:
        #Decode base64 string
        decoded_bytes = base64.b64decode(base64_string)

        # Encode to base64url and remove padding
        base64url_string = base64.urlsafe_b64encode(decoded_bytes).decode().rstrip("=")

        return base64url_string
    

    def base64url_to_base64(self, base64url_string: str) -> str:
        # Add padding to base64url string if needed
        padding_length = len(base64url_string) % 4
        if padding_length != 0:
            base64url_string += "=" * (4 - padding_length)

        # Decode base64url string
        decoded_bytes = base64.urlsafe_b64decode(base64url_string)

        # Encode to base64 and add padding
        base64_string = base64.b64encode(decoded_bytes).decode()

        return base64_string



    def CreateJws(self, payload: str, privateKeyPEM: str) -> str:
        headerOjb =  """{ "alg" = "ES256", "typ" = "JSON" }"""

        headerB64 = base64.standard_b64encode(headerOjb.encode())
        payloadB64 = base64.standard_b64encode(payload.encode())

        headerB64Url = self.base64_to_base64url(headerB64)
        payloadB64Url = self.base64_to_base64url(payloadB64)

        headPlusPay = "{}.{}".format(headerB64Url, payloadB64Url)
        headPlusPayBytes = headPlusPay.encode()

        #we convert the PEM key to pyCrypt type
        private_key = serialization.load_pem_private_key(
        privateKeyPEM,
        password = None,  # Change to your password if the private key is encrypted
        backend = default_backend()
        )

        signature = private_key.sign(
        headPlusPayBytes,
        ec.ECDSA(hashes.SHA256())
        )

        sigB64 = base64.standard_b64encode(signature)
        sigB64Url = self.base64_to_base64url(sigB64)

        fullJws = "{}.{}".format(headPlusPay, sigB64Url)

        print(fullJws)

        return fullJws

    def VerifyJws(self, jws: str, pubKeyPEM: str) -> bool:
        
        #pull apart the JWS
        parts = jws.split(".")
        data = "{}.{}".format(parts[0], parts[1])
        
        data = data.encode()

        signatureB64 = self.base64url_to_base64(parts[2])
        signature = base64.standard_b64decode(signatureB64)

        pubKey = serialization.load_pem_public_key(
        pubKeyPEM,
        backend = default_backend()
        )


        try:
            pubKey.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False


        return False
