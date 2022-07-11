"""
hashes contains utility functions related to hashing
"""

from __future__ import annotations


import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from . import keccak


def sha256_hash(b: bytes) -> bytes:
    """
    sha256_hash hashes the given bytes with SHA256

    Args:
        b (bytes): bytes to hash

    Returns:
        bytes: The hash result
    """
    return hashlib.sha256(b).digest()


def keccak256_hash(b: bytes) -> bytes:
    """
    keccak256_hash hashes the given bytes with KECCAK256

    Args:
        b (bytes): bytes to hash

    Returns:
        bytes: The hash result
    """
    return keccak.keccak256.digest(b)


def blake2b_hash(b: bytes) -> bytes:
    """
    blake2b_hash hashes the given bytes with BLAKE2b (optimized for 64-bit platforms)

    Args:
        b (bytes): bytes to hash

    Returns:
        bytes: The hash result
    """
    return hashlib.blake2b(b, digest_size=32).digest()

def aesEncrypt(data: str, key: str) -> str:
    """
    aesEncrypt encrypts the given data in AES.

    Args:
    data (str): The data to encrypt.
    key (str): The key used to encrypt data.

    Returns:
        str: The encryption result
    """

    BS = AES.block_size
    data = pad(data.encode(), BS)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(data).hex()

def aesDecrypt(data: str, key: str) -> str:
    """
    aesDecrypt decrypts the given data encrypted by AES.

    Args:
    data (str): The data to decrypt.
    key (str): The key used to decrypt data.

    Returns:
        str: The decryption result    
    """

    BS = AES.block_size
    aes = AES.new(key, AES.MODE_ECB)
    return unpad(aes.decrypt(bytes.fromhex(data)), BS).decode()