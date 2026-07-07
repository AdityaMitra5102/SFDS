import jwt
import json
import base64
import hashlib
from jwt.algorithms import ECAlgorithm
import json
from jwcrypto import jwk
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.holder import SDJWTHolder
from sd_jwt.verifier import SDJWTVerifier
from sd_jwt.common import SDObj
import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import cbor2


def base64url_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def base64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def hash_disclosure(disclosure):
    return base64url_encode(hashlib.sha256(disclosure.encode()).digest())


def decode_disclosure(disclosure):
    parsed = json.loads(base64url_decode(disclosure))
    if len(parsed) == 3:
        salt, claim_name, claim_value = parsed
        return "claim", salt, claim_name, claim_value
    elif len(parsed) == 2:
        salt, claim_value = parsed
        return "array_element", salt, None, claim_value
    else:
        raise ValueError(f"Unexpected disclosure format: {parsed}")


def load_jwk(path):
    with open(path, 'r') as f:
        return json.load(f)


def read_file(path):
    with open(path, 'r') as f:
        return f.read().strip()


def find_in_sd(payload, disclosure_hash):
    return disclosure_hash in payload.get("_sd", [])


def find_in_array_elements(payload, disclosure_hash):
    if isinstance(payload, dict):
        if payload.get("...") == disclosure_hash:
            return True
        return any(find_in_array_elements(v, disclosure_hash) for v in payload.values())
    elif isinstance(payload, list):
        return any(find_in_array_elements(item, disclosure_hash) for item in payload)
    return False


def find_in_nested_sd(payload, disclosure_hash):
    if isinstance(payload, dict):
        if disclosure_hash in payload.get("_sd", []):
            return True
        return any(find_in_nested_sd(v, disclosure_hash) for v in payload.values())
    elif isinstance(payload, list):
        return any(find_in_nested_sd(item, disclosure_hash) for item in payload)
    return False


def verify_jwt_signature(token, pub_key_jwk):
    public_key = ECAlgorithm.from_jwk(json.dumps(pub_key_jwk))
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            options={"verify_exp": False, "verify_aud": False}
        )
    except jwt.exceptions.InvalidSignatureError:
        raise ValueError("JWT signature verification failed")
    except jwt.exceptions.DecodeError as e:
        raise ValueError(f"JWT decode error: {e}")


def verify_disclosure(payload, disclosure):
    kind, salt, claim_name, claim_value = decode_disclosure(disclosure)
    disclosure_hash = hash_disclosure(disclosure)

    if kind == "claim":
        if not (find_in_sd(payload, disclosure_hash) or find_in_nested_sd(payload, disclosure_hash)):
            raise ValueError(f"Disclosure hash '{disclosure_hash}' not found in any _sd array")
        return {"type": "claim", "key": claim_name, "value": claim_value}

    elif kind == "array_element":
        if not find_in_array_elements(payload, disclosure_hash):
            raise ValueError(f"Disclosure hash '{disclosure_hash}' not found in any array element")
        return {"type": "array_element", "key": None, "value": claim_value}


def verify_sd_jwt(jwt_path, pub_key_path, disclosures):
    token = read_file(jwt_path)
    pub_key = load_jwk(pub_key_path)

    print("\n── Step 1: Verifying JWT signature ───────────────────────────────")
    payload = verify_jwt_signature(token, pub_key)
    print("Signature valid ✓")
    print(f"Raw payload: {json.dumps(payload, indent=2)}")

    print("\n── Step 2: Verifying disclosures ─────────────────────────────────")
    verified_claims = {}

    for i, disclosure in enumerate(disclosures):
        if not disclosure:
            continue
        result = verify_disclosure(payload, disclosure)
        key = result["key"] or f"array_element_{i}"
        verified_claims[key] = result["value"]
        print(f"  [{result['type']}] {key}: {result['value']}  ✓")

    print("\n── Verified claims ───────────────────────────────────────────────")
    print(json.dumps(verified_claims, indent=2))
    return payload, verified_claims


def decrypt_file(key, data):
	tag = data[-16:]
	data = data [:-16]
	nonce = data[-12:]
	data = data [:-12]
	ciphertext = data
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	return cipher.decrypt_and_verify(ciphertext, tag)
	
def write_file(path, content):
    dir = os.path.dirname(path)
    if dir:
        os.makedirs(dir, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(content)

def fetch_blob(blob_uri):
    b64head='data:application/octet-stream;base64,'
    if blob_uri.startswith(b64head):
        return base64url_decode(blob_uri[len(b64head):])
    if blob_uri.startswith('http'):
        resp = requests.get(blob_uri)
        content = resp.content
        if content.startswith(b64head.encode()):
            return fetch_blob(content.decode())
        return content

def make_files(blob, claims):
    all_files = fetch_blob(blob)
    for claim in claims:
        claim_value = claims[str(claim)]
        claim_json=json.loads(claim_value)
        path=claim_json['path']
        offset=claim_json['offset']
        length=claim_json['length']
        hash=claim_json['hash']
        key=base64url_decode(claim_json['key'])
        file_content_enc=all_files[offset:offset+length]
        file_content=decrypt_file(key, file_content_enc)
        calc_hash=hashlib.sha256(file_content).hexdigest()
        if(calc_hash==hash):
            write_file(path, file_content)
        else:
            print(f"File hash validation failed. File skipped {path}\t{calc_hash} -> {hash}")


def main():
    raw_disclosures = read_file('presentation.txt')
    disclosures = [d for d in raw_disclosures.split('~') if d]
    payload, claims= verify_sd_jwt('jwt.txt', 'issuer_pub.json', disclosures)
    blob=payload['blob']
    make_files(blob, claims)


if __name__ == '__main__':
    main()