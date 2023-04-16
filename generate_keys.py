from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
import secrets
import os

def generate_key_pair(name):
    print("Generating keys")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend = default_backend())
    public_key = private_key.public_key()
    # Serialize private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('keys/'+name+'_private_key.pem', 'wb') as f:
        f.write(pem)

    # Serialize public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('keys/'+name+'_public_key.pem', 'wb') as f:
        f.write(pem)

    return pem

def generate_aes_key():
    aes_key = secrets.token_bytes(32)
    with open('keys/aes_key.pem', 'wb') as f:
        f.write(aes_key)
    return aes_key

def generate_iv():
    return secrets.token_bytes(16)