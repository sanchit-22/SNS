"""
crypto_utils.py
===============
Contains cryptographic primitives only: AES-CBC, PKCS#7 padding, HMAC.
No protocol or networking logic is allowed.

Author: CS5.470 Lab Assignment 1
Date: January 2026
"""

import os
import hmac
import hashlib
from Crypto.Cipher import AES


# ============================================================================
# PKCS#7 Padding Implementation
# ============================================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data.
    
    PKCS#7 padding works as follows:
    - If data length is k bytes short of a multiple of block_size,
      append k bytes each with value k.
    - If data length is already a multiple of block_size,
      append a full block of padding (block_size bytes each with value block_size).
    
    Args:
        data: The plaintext data to pad
        block_size: AES block size (16 bytes for AES-128)
    
    Returns:
        Padded data as bytes
    
    Example:
        If block_size=16 and data is 14 bytes, add 2 bytes of value 0x02
        If block_size=16 and data is 16 bytes, add 16 bytes of value 0x10
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1 and 255")
    
    # Calculate padding length
    padding_length = block_size - (len(data) % block_size)
    
    # Create padding: padding_length bytes, each with value padding_length
    padding = bytes([padding_length] * padding_length)
    
    return data + padding


def pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Validates that:
    1. Data length is a multiple of block_size
    2. Padding length is valid (1 to block_size)
    3. All padding bytes have the correct value
    
    Args:
        padded_data: The padded data
        block_size: AES block size (16 bytes for AES-128)
    
    Returns:
        Unpadded data as bytes
    
    Raises:
        ValueError: If padding is invalid (treated as data tampering)
    """
    if not isinstance(padded_data, bytes):
        raise TypeError("Padded data must be bytes")
    
    if len(padded_data) == 0:
        raise ValueError("Invalid padding: empty data")
    
    if len(padded_data) % block_size != 0:
        raise ValueError("Invalid padding: data length not multiple of block size")
    
    # Get the padding length from the last byte
    padding_length = padded_data[-1]
    
    # Validate padding length
    if padding_length < 1 or padding_length > block_size:
        raise ValueError(f"Invalid padding: padding length {padding_length} out of range")
    
    # Validate all padding bytes have the correct value
    padding = padded_data[-padding_length:]
    if not all(byte == padding_length for byte in padding):
        raise ValueError("Invalid padding: padding bytes have incorrect values")
    
    # Return data without padding
    return padded_data[:-padding_length]


# ============================================================================
# AES-CBC Encryption and Decryption
# ============================================================================

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in CBC mode.
    
    Note: Plaintext must be already padded to a multiple of 16 bytes.
    
    Args:
        plaintext: Padded plaintext data
        key: 16-byte AES key
        iv: 16-byte initialization vector
    
    Returns:
        Ciphertext as bytes
    
    Raises:
        ValueError: If key or IV size is incorrect, or plaintext not properly padded
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    if len(iv) != 16:
        raise ValueError(f"AES requires 16-byte IV, got {len(iv)} bytes")
    
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext must be padded to multiple of 16 bytes")
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    
    return ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in CBC mode.
    
    Args:
        ciphertext: Encrypted data
        key: 16-byte AES key
        iv: 16-byte initialization vector
    
    Returns:
        Decrypted padded plaintext as bytes
    
    Raises:
        ValueError: If key or IV size is incorrect, or ciphertext length invalid
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    if len(iv) != 16:
        raise ValueError(f"AES requires 16-byte IV, got {len(iv)} bytes")
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16 bytes")
    
    if len(ciphertext) == 0:
        raise ValueError("Ciphertext cannot be empty")
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext


# ============================================================================
# HMAC-SHA256 Implementation
# ============================================================================

def compute_hmac(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256 of a message.
    
    Args:
        key: HMAC key (can be any length)
        message: Data to authenticate
    
    Returns:
        32-byte HMAC tag
    """
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be bytes")
    
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    
    # Compute HMAC-SHA256
    h = hmac.new(key, message, hashlib.sha256)
    
    return h.digest()


def verify_hmac(key: bytes, message: bytes, expected_hmac: bytes) -> bool:
    """
    Verify HMAC-SHA256 of a message using constant-time comparison.
    
    Args:
        key: HMAC key
        message: Data to authenticate
        expected_hmac: Expected HMAC tag
    
    Returns:
        True if HMAC is valid, False otherwise
    """
    if not isinstance(expected_hmac, bytes):
        raise TypeError("Expected HMAC must be bytes")
    
    if len(expected_hmac) != 32:
        return False
    
    # Compute HMAC
    computed_hmac = compute_hmac(key, message)
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hmac, expected_hmac)


# ============================================================================
# Key Derivation
# ============================================================================

def derive_key(master_key: bytes, label: str) -> bytes:
    """
    Derive a 16-byte key from a master key and label using SHA-256.
    
    This is used for initial key derivation:
    - C2S_Enc_0 = H(K_i || "C2S-ENC")
    - C2S_Mac_0 = H(K_i || "C2S-MAC")
    - S2C_Enc_0 = H(K_i || "S2C-ENC")
    - S2C_Mac_0 = H(K_i || "S2C-MAC")
    
    Args:
        master_key: Pre-shared master key
        label: Derivation label (e.g., "C2S-ENC")
    
    Returns:
        16-byte derived key (first 16 bytes of SHA-256 hash)
    """
    if not isinstance(master_key, bytes):
        raise TypeError("Master key must be bytes")
    
    if not isinstance(label, str):
        raise TypeError("Label must be string")
    
    # Convert label to bytes
    label_bytes = label.encode('utf-8')
    
    # Compute SHA-256(master_key || label)
    h = hashlib.sha256(master_key + label_bytes)
    
    # Return first 16 bytes for AES-128
    return h.digest()[:16]


def evolve_key(current_key: bytes, data: bytes) -> bytes:
    """
    Evolve a key using SHA-256 hash ratcheting.
    
    Key evolution formulas:
    - C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
    - C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    - S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
    - S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
    
    Args:
        current_key: Current key value
        data: Data to mix into the key (e.g., ciphertext, nonce)
    
    Returns:
        16-byte evolved key (first 16 bytes of SHA-256 hash)
    """
    if not isinstance(current_key, bytes):
        raise TypeError("Current key must be bytes")
    
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    
    # Compute SHA-256(current_key || data)
    h = hashlib.sha256(current_key + data)
    
    # Return first 16 bytes for AES-128
    return h.digest()[:16]


# ============================================================================
# Secure Random Generation
# ============================================================================

def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Uses OS-level secure RNG (os.urandom).
    
    Args:
        length: Number of random bytes to generate
    
    Returns:
        Random bytes
    """
    if length < 1:
        raise ValueError("Length must be positive")
    
    return os.urandom(length)


def generate_iv() -> bytes:
    """
    Generate a fresh random IV for AES-CBC.
    
    Returns:
        16-byte random IV
    """
    return generate_random_bytes(16)


# ============================================================================
# Utility Functions
# ============================================================================

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte strings.
    
    Args:
        a: First byte string
        b: Second byte string
    
    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)


# ============================================================================
# Testing Functions (for debugging only)
# ============================================================================

if __name__ == "__main__":
    # Test PKCS#7 padding
    print("Testing PKCS#7 Padding...")
    test_data = b"Hello, World!"
    padded = pkcs7_pad(test_data)
    print(f"Original: {test_data} (len={len(test_data)})")
    print(f"Padded: {padded.hex()} (len={len(padded)})")
    unpadded = pkcs7_unpad(padded)
    print(f"Unpadded: {unpadded}")
    assert test_data == unpadded, "Padding/Unpadding failed!"
    print("✓ PKCS#7 padding test passed\n")
    
    # Test AES-CBC encryption
    print("Testing AES-CBC Encryption...")
    key = generate_random_bytes(16)
    iv = generate_iv()
    plaintext = pkcs7_pad(b"Secret message")
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    print(f"Plaintext: {plaintext.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted.hex()}")
    assert plaintext == decrypted, "Encryption/Decryption failed!"
    print("✓ AES-CBC test passed\n")
    
    # Test HMAC
    print("Testing HMAC-SHA256...")
    hmac_key = generate_random_bytes(16)
    message = b"Test message"
    tag = compute_hmac(hmac_key, message)
    print(f"HMAC: {tag.hex()}")
    assert verify_hmac(hmac_key, message, tag), "HMAC verification failed!"
    assert not verify_hmac(hmac_key, b"Wrong message", tag), "HMAC should fail for wrong message!"
    print("✓ HMAC test passed\n")
    
    # Test key derivation
    print("Testing Key Derivation...")
    master = generate_random_bytes(16)
    derived = derive_key(master, "TEST-KEY")
    print(f"Master: {master.hex()}")
    print(f"Derived: {derived.hex()}")
    print("✓ Key derivation test passed\n")
    
    # Test key evolution
    print("Testing Key Evolution...")
    key0 = generate_random_bytes(16)
    data = b"some data"
    key1 = evolve_key(key0, data)
    key2 = evolve_key(key1, data)
    print(f"Key0: {key0.hex()}")
    print(f"Key1: {key1.hex()}")
    print(f"Key2: {key2.hex()}")
    assert key0 != key1 != key2, "Keys should be different!"
    print("✓ Key evolution test passed\n")
    
    print("All cryptographic primitive tests passed!")
