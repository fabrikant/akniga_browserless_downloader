import json
import hashlib
import base64
import binascii
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# Decrypt password obtained from akniga's JS script.
# Found all string parts and tried to brute force the password.
PASSWORD = "EKxtcg46V"
KEY_LEN = 32
IV_LEN = 16
KDF_HASH_ALGO = "md5"
BLOCK_SIZE = 16


class EncryptedData:
    """Represents encrypted data structure from JSON."""
    def __init__(self, ct: str, iv: str, s: str):
        self.ct = ct
        self.iv = iv
        self.s = s


def decode_url(input_json: str) -> str:
    """
    Decrypts an encrypted URL from JSON string.
    
    Args:
        input_json: JSON string containing encrypted data with 'ct', 'iv', and 's' fields
        
    Returns:
        str: Decrypted URL
        
    Raises:
        ValueError: If decryption fails or data is invalid
    """
    try:
        data_dict = json.loads(input_json)
        data = EncryptedData(data_dict['ct'], data_dict['iv'], data_dict['s'])
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Failed to parse JSON: {e}")

    # Decode ciphertext from base64
    ct_base64 = data.ct.replace("\\/" , "/")
    try:
        ciphertext = base64.standard_b64decode(ct_base64)
    except Exception as e:
        raise ValueError(f"Failed to decode base64 ciphertext: {e}")

    # Decode IV from hex
    try:
        iv = binascii.unhexlify(data.iv)
    except Exception as e:
        raise ValueError(f"Failed to decode hex IV: {e}")
    
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"Invalid IV length: expected {BLOCK_SIZE}, got {len(iv)}")

    # Decode salt from hex
    try:
        salt = binascii.unhexlify(data.s)
    except Exception as e:
        raise ValueError(f"Failed to decode hex salt: {e}")

    # Derive key using EVP_BytesToKey
    try:
        key = evp_bytes_to_key(PASSWORD.encode(), salt, KEY_LEN, IV_LEN)
    except Exception as e:
        raise ValueError(f"Failed to derive key: {e}")

    # Create AES cipher and decrypt
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
    except Exception as e:
        raise ValueError(f"Failed to decrypt: {e}")

    # Remove PKCS7 padding
    try:
        decrypted_data = unpad(decrypted_padded, BLOCK_SIZE)
    except ValueError as e:
        raise ValueError(f"Failed to unpad data (likely wrong key/ciphertext): {e}")

    # Clean up the decrypted string
    final_url = decrypted_data.decode('utf-8', errors='ignore')
    final_url = final_url.replace("\\", "")
    final_url = final_url.replace("\"", "")

    if not final_url:
        raise ValueError("Decryption resulted in an empty string")

    return final_url


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int) -> bytes:
    """
    Derives a key from password and salt using EVP_BytesToKey algorithm.
    
    This replicates OpenSSL's EVP_BytesToKey function with MD5 hash.
    
    Args:
        password: Password bytes
        salt: Salt bytes
        key_len: Desired key length
        iv_len: Desired IV length (not used in this function but kept for compatibility)
        
    Returns:
        bytes: Derived key of length key_len
        
    Raises:
        ValueError: If key derivation fails
    """
    derived_bytes = b''
    block = b''
    total_len = key_len + iv_len

    while len(derived_bytes) < total_len:
        hasher = hashlib.md5()
        
        if block:
            hasher.update(block)
        
        hasher.update(password)
        hasher.update(salt)
        
        block = hasher.digest()
        derived_bytes += block

    if len(derived_bytes) < key_len:
        raise ValueError(
            f"Derived bytes length ({len(derived_bytes)}) is less than "
            f"required key length ({key_len})"
        )
    
    return derived_bytes[:key_len]


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Removes PKCS7 padding from data.
    
    Args:
        data: Padded data
        
    Returns:
        bytes: Unpadded data
        
    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("PKCS7: data is empty")

    padding_len = data[-1]

    if padding_len > len(data) or padding_len > BLOCK_SIZE or padding_len == 0:
        raise ValueError(
            f"PKCS7: invalid padding length {padding_len} (data length {len(data)})"
        )

    pad = data[-padding_len:]
    for byte in pad:
        if byte != padding_len:
            raise ValueError("PKCS7: invalid padding bytes")

    return data[:-padding_len]
