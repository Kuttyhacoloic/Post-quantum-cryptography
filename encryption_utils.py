# secure_file_transfer/encryption_utils.py

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def derive_shared_key(secret: bytes) -> bytes:
    """Derive AES key from shared secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=None,
        info=b'secure_file_transfer'
    )
    return hkdf.derive(secret)

def encrypt_file(data: bytes, key: bytes) -> bytes:
    """Encrypt file data with AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce + encrypted  # Prepend nonce for decryption

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt file data with AES-GCM."""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
