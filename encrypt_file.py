from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
import io

def rsa_encrypt(file, public_key):
    encrypted = public_key.encrypt(
        file,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def rsa_decrypt(encrypted_item, private_key):
    decrypted = private_key.decrypt(
        encrypted_item,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def aes_encrypt(aes_key, iv, file):
    print("Encrypted IV: ", iv)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(file) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize() # encrypted data
    return iv + encrypted_data

def aes_decrypt(aes_key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    print("Decrypted IV: ", iv)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def get_private_key(name):
    with open("./keys/"+name+"_private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                return private_key

def get_public_key(name):
    public_key = serialization.load_pem_public_key(
        open("./keys/"+name+"_public_key.pem", "rb").read(),
        backend=default_backend()
    )
    return public_key