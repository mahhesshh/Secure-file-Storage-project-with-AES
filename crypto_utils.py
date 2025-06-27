import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime


def generate_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()


def encrypt_file(filepath, password):
    key = generate_key(password)
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    padder = padding.PKCS7(128).padder()

    with open(filepath, 'rb') as f:
        plaintext = f.read()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    filename = os.path.basename(filepath)
    enc_file_path = f'stored_files/{filename}.enc'
    with open(enc_file_path, 'wb') as f:
        f.write(iv + ciphertext)

    # Generate metadata
    sha256_hash = hashlib.sha256(plaintext).hexdigest()
    metadata = {
        'filename': filename,
        'timestamp': datetime.now().isoformat(),
        'hash': sha256_hash
    }
    return enc_file_path, metadata


def decrypt_file(enc_path, password, output_dir="decrypted_files"):
    key = generate_key(password)
    with open(enc_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_file = os.path.join(output_dir,
                               os.path.basename(enc_path).replace('.enc', ''))
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    return output_file, hashlib.sha256(plaintext).hexdigest()


# ✅ Add this function to the bottom of crypto_utils.py
def store_metadata(metadata, meta_path="metadata.json"):
    existing = []
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            existing = json.load(f)
    existing.append(metadata)
    with open(meta_path, 'w') as f:
        json.dump(existing, f, indent=4)
