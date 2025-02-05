"""
hashes contains utility functions related to hashing
"""

from __future__ import annotations


import hashlib

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
