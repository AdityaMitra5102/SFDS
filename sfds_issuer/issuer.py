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
import cbor2

def encrypt_file(path):
	key = get_random_bytes(32)
	nonce = get_random_bytes(12)
	with open(path, "rb") as f:
		plaintext = f.read()
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	ciphertext, tag = cipher.encrypt_and_digest(plaintext)
	payload = ciphertext+nonce+tag
	return key, payload

def decrypt_file(key, data):
	payload = cbor2.loads(data)
	nonce = payload["nonce"]
	tag = payload["tag"]
	ciphertext = payload["ciphertext"]
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	return cipher.decrypt_and_verify(ciphertext, tag)
	
def hash_file(path):
	h = hashlib.sha256()
	with open(path, 'rb') as f:
		while chunk := f.read(8192):
			h.update(chunk)
	return base64.urlsafe_b64encode(h.digest()).decode().rstrip('=')
    
def get_all_files(root_dir="."):
	b64head='data:application/octet-stream;base64,'
	file_content =	bytearray()
	file_list = []
	for dirpath, dirnames, filenames in os.walk(root_dir):
		for filename in filenames:
			full_path = os.path.join(dirpath, filename)
			rel_path = os.path.relpath(full_path, start=os.path.dirname(root_dir))
			key, file_enc = encrypt_file(full_path)
			file_integrity = hash_file(full_path)
			file_data = {
				'path': rel_path,
				'offset': len(file_content),
				'length': len(file_enc),
				'hash': file_integrity,
				'key': base64.urlsafe_b64encode(key).decode().rstrip('='),
				'alg': 3, #AES256GCM COSE
			}
			file_content.extend(file_enc)
			file_list.append(file_data)
		file_content_b64=b64head+base64.urlsafe_b64encode(file_content).decode()
	return file_list, file_content_b64
		
def save_jwk(path):
	key = jwk.JWK.generate(kty="EC", crv="P-256")
	with open(path, "w") as f:
		json.dump(json.loads(key.export()), f, indent=2)
	print(f"Key saved to {path}")

def load_jwk(path):
	try:
		with open(path) as f:
			return jwk.JWK(**json.load(f))
	except:
		save_jwk(path)
		return load_jwk(path)
		
def save_pub(path, key):
	with open(path, "w") as f:
		json.dump(json.loads(key.export_public()), f, indent=2)
	print(f"Pub Key saved to {path}")


key = load_jwk("issuer_key.json")
save_pub("issuer_pub.json", key)

def create_sd(key, path="."):
	file_list, content = get_all_files(path)
	claims = {
		"files": [SDObj(file) for file in file_list],
		"blob": content
	}
	print(claims)
	issuer = SDJWTIssuer(claims, key)
	return issuer.sd_jwt_issuance
	
def get_jwt(sd):
	jwt= sd[:sd.find('~')]
	disclosures = sd[sd.find('~'):]
	return jwt, disclosures
	
def main(path):
	key = load_jwk("issuer_key.json")
	save_pub("issuer_pub.json", key)
	sd = create_sd(key, path)
	with open('jwt.txt', 'w') as f:
		f.write(sd)
		
if __name__=='__main__':
	main('example')
	
	

			