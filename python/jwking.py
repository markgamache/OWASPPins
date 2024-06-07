from jwcrypto import jwk
from jwcrypto.common import json_encode
import json


class jwking:
    
    

    def __init__(self):
        self.keyAsjwk = jwk.JWK.generate(kty='EC', crv='P-256')
    
    def ConvertJwkToPEM(keyAsjwk : jwk.JWK, withPrivateKey : bool ) -> str :
        return keyAsjwk.export_to_pem(withPrivateKey, None)

    def ConvertJwkToJson(self ) -> str :
        return self.keyAsjwk.export(private_key=False) 

    def ImportJwkFromJson(jsonIn: str) -> jwk.JWK:
        keyObj = json.loads(jsonIn)
        return jwk.JWK(**keyObj)




class PinPayload:
    def __init__(self, domain, key_pins, last_updated):
        self.domain = domain #needs to be a single string that would be in a DNS SAN
        self.key_pins = key_pins # list of pins
        self.last_updated = last_updated #date as string or long
        
        
class PinConfig:
    def __init__(self, pinset_url, pinset_keys, last_updated, applies_to):
        self.pinset_url = pinset_url
        self.pinset_keys = pinset_keys
        self.last_updated = last_updated
        self.applies_to = applies_to

class JWKx:
    def __init__(self, realJWK : jwk.JWK ):
        self.kty = realJWK.keyAsjwk.kty
        self.x = realJWK.keyAsjwk.x
        self.y = realJWK.keyAsjwk.y
        self.crv = realJWK.keyAsjwk.crv
        self.kid = realJWK.keyAsjwk.key_id
        
