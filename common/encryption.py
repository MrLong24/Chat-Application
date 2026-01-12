"""
Encryption Utilities for Multi-Client Chat Application

This module provides modular encryption/decryption functions using different algorithms.
Supports XOR cipher and Caesar cipher for educational purposes.

Security Note: These ciphers are for demonstration only. In production,
use industry-standard encryption like AES, RSA, or TLS/SSL.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import ENCRYPTION_METHOD, XOR_KEY, CAESAR_SHIFT


# ==================== XOR ENCRYPTION ====================

def xor_encrypt(data: bytes, key: int = XOR_KEY) -> bytes:
    """
    Encrypt data using XOR cipher with a single-byte key.
    
    XOR Cipher Explanation:
    - Each byte is XORed with the key byte
    - XOR is symmetric: encrypt(encrypt(data)) = data
    - Fast but not cryptographically secure
    
    Args:
        data (bytes): Data to encrypt
        key (int): Single-byte key (0-255)
    
    Returns:
        bytes: Encrypted data
    
    Example:
        >>> plaintext = b"Hello"
        >>> encrypted = xor_encrypt(plaintext, 0xAB)
        >>> decrypted = xor_decrypt(encrypted, 0xAB)
        >>> assert plaintext == decrypted
    """
    return bytes([byte ^ key for byte in data])


def xor_decrypt(data: bytes, key: int = XOR_KEY) -> bytes:
    """
    Decrypt data using XOR cipher.
    
    Since XOR is symmetric, decryption is identical to encryption.
    
    Args:
        data (bytes): Data to decrypt
        key (int): Single-byte key (0-255)
    
    Returns:
        bytes: Decrypted data
    """
    # XOR is symmetric, so decrypt is same as encrypt
    return xor_encrypt(data, key)


# ==================== CAESAR CIPHER ====================

def caesar_encrypt(text: str, shift: int = CAESAR_SHIFT) -> str:
    """
    Encrypt text using Caesar cipher (shift cipher).
    
    Caesar Cipher Explanation:
    - Each letter is shifted by a fixed number of positions in the alphabet
    - ROT13 is a special case where shift = 13
    - Only affects alphabetic characters, preserves case
    - Not cryptographically secure
    
    Args:
        text (str): Text to encrypt
        shift (int): Number of positions to shift (default: 13 for ROT13)
    
    Returns:
        str: Encrypted text
    
    Example:
        >>> plaintext = "Hello World"
        >>> encrypted = caesar_encrypt(plaintext, 13)
        >>> print(encrypted)  # "Uryyb Jbeyq"
    """
    result = []
    
    for char in text:
        if char.isalpha():
            # Determine if uppercase or lowercase
            ascii_offset = ord('A') if char.isupper() else ord('a')
            
            # Shift character within alphabet (0-25)
            shifted = (ord(char) - ascii_offset + shift) % 26
            
            # Convert back to character
            result.append(chr(shifted + ascii_offset))
        else:
            # Non-alphabetic characters unchanged
            result.append(char)
    
    return ''.join(result)


def caesar_decrypt(text: str, shift: int = CAESAR_SHIFT) -> str:
    """
    Decrypt text using Caesar cipher.
    
    Decryption is just encryption with negative shift.
    
    Args:
        text (str): Text to decrypt
        shift (int): Number of positions that were shifted
    
    Returns:
        str: Decrypted text
    """
    # Decrypt by shifting in opposite direction
    return caesar_encrypt(text, -shift)


# ==================== UNIFIED ENCRYPTION INTERFACE ====================

def encrypt(data: bytes) -> bytes:
    """
    Encrypt data using the configured encryption method.
    
    This function provides a unified interface that automatically
    selects the encryption algorithm based on settings.
    
    Args:
        data (bytes): Data to encrypt
    
    Returns:
        bytes: Encrypted data
    
    Raises:
        ValueError: If encryption method is invalid
    """
    if ENCRYPTION_METHOD == 'XOR':
        return xor_encrypt(data, XOR_KEY)
    
    elif ENCRYPTION_METHOD == 'CAESAR':
        # Convert bytes to string for Caesar cipher
        text = data.decode('utf-8', errors='ignore')
        encrypted_text = caesar_encrypt(text, CAESAR_SHIFT)
        return encrypted_text.encode('utf-8')
    
    elif ENCRYPTION_METHOD == 'NONE':
        # No encryption
        return data
    
    else:
        raise ValueError(f"Unknown encryption method: {ENCRYPTION_METHOD}")


def decrypt(data: bytes) -> bytes:
    """
    Decrypt data using the configured encryption method.
    
    This function provides a unified interface that automatically
    selects the decryption algorithm based on settings.
    
    Args:
        data (bytes): Data to decrypt
    
    Returns:
        bytes: Decrypted data
    
    Raises:
        ValueError: If encryption method is invalid
    """
    if ENCRYPTION_METHOD == 'XOR':
        return xor_decrypt(data, XOR_KEY)
    
    elif ENCRYPTION_METHOD == 'CAESAR':
        # Convert bytes to string for Caesar cipher
        text = data.decode('utf-8', errors='ignore')
        decrypted_text = caesar_decrypt(text, CAESAR_SHIFT)
        return decrypted_text.encode('utf-8')
    
    elif ENCRYPTION_METHOD == 'NONE':
        # No encryption
        return data
    
    else:
        raise ValueError(f"Unknown encryption method: {ENCRYPTION_METHOD}")


# ==================== UTILITY FUNCTIONS ====================

def test_encryption():
    """
    Test encryption/decryption functions with various inputs.
    Used for validation and debugging.
    """
    print("=" * 50)
    print("Encryption Module Test")
    print("=" * 50)
    
    # Test data
    test_cases = [
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        b"1234567890",
        b"Special chars: @#$%^&*()",
        "Unicode: 你好世界 🌍".encode('utf-8')
    ]
    
    print(f"\nActive Encryption: {ENCRYPTION_METHOD}\n")
    
    for i, original in enumerate(test_cases, 1):
        try:
            # Encrypt
            encrypted = encrypt(original)
            
            # Decrypt
            decrypted = decrypt(encrypted)
            
            # Verify
            success = original == decrypted
            status = "✓ PASS" if success else "✗ FAIL"
            
            print(f"Test {i}: {status}")
            print(f"  Original:  {original[:50]}...")
            print(f"  Encrypted: {encrypted[:50]}...")
            print(f"  Decrypted: {decrypted[:50]}...")
            print(f"  Match: {success}\n")
            
        except Exception as e:
            print(f"Test {i}: ✗ ERROR")
            print(f"  Error: {e}\n")
    
    print("=" * 50)


def benchmark_encryption(data_size: int = 1024 * 1024):
    """
    Benchmark encryption performance.
    
    Args:
        data_size (int): Size of test data in bytes (default: 1MB)
    """
    import time
    
    # Generate test data
    test_data = os.urandom(data_size)
    
    print(f"\nBenchmarking encryption with {data_size / 1024:.0f} KB of data...")
    
    # Encrypt
    start = time.time()
    encrypted = encrypt(test_data)
    encrypt_time = time.time() - start
    
    # Decrypt
    start = time.time()
    decrypted = decrypt(encrypted)
    decrypt_time = time.time() - start
    
    # Calculate throughput
    encrypt_mbps = (data_size / (1024 * 1024)) / encrypt_time
    decrypt_mbps = (data_size / (1024 * 1024)) / decrypt_time
    
    print(f"Encryption: {encrypt_time:.3f}s ({encrypt_mbps:.2f} MB/s)")
    print(f"Decryption: {decrypt_time:.3f}s ({decrypt_mbps:.2f} MB/s)")
    print(f"Verification: {'✓ PASS' if test_data == decrypted else '✗ FAIL'}\n")


# ==================== MAIN ====================

if __name__ == "__main__":
    """
    Run tests when module is executed directly.
    """
    print("\n" + "=" * 50)
    print("ENCRYPTION MODULE - STANDALONE TEST")
    print("=" * 50)
    
    # Run tests
    test_encryption()
    
    # Run benchmark
    benchmark_encryption(1024 * 100)  # 100 KB
    
    print("\n✓ All tests completed\n")