"""Handle encryption and decryption:
- password-to-key generation
- AES encryption
- IV generation
- padding
- key update mechanism
"""

import os
import base64
import hashlib
import hmac
import json
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SecureChannel:
    """Secure P2P messaging channel using AES-128-CBC with PBKDF2 key derivation,
    HMAC-SHA256 authentication, and per-message key updates.
    """

    # Static salt for PBKDF2 (pre-shared constant for this application)
    SALT = b"CS4173_SecureP2P_Salt_2026"
    
    # PBKDF2 iterations (balance between security and performance)
    PBKDF2_ITERATIONS = 100_000
    
    # Key sizes (in bytes)
    AES_KEY_SIZE = 16  # 128 bits
    IV_SIZE = 16       # 128 bits (AES block size)
    HMAC_SIZE = 32     # SHA-256 output

    def __init__(self, password: str) -> None:
        """Initialize the secure channel with a shared password.
        
        Args:
            password: Shared password string used to derive the AES key.
        """
        # Derive the master key from the password using PBKDF2
        self._master_key = self._derive_key_from_password(password)
        
        # Initialize the current working key as the master key
        self._current_key = self._master_key
        
        # Initialize key epoch counter
        self._key_epoch = 0

    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive a 128-bit AES key from a password using PBKDF2-SHA256.
        
        Args:
            password: Password string.
            
        Returns:
            16-byte AES key derived from password.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE,
            salt=self.SALT,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    def _pad(self, plaintext: bytes) -> bytes:
        """Apply PKCS7 padding to plaintext.
        
        PKCS7: Pad with N bytes, each valued N, where N is the number of padding bytes.
        For AES (16-byte block size), padding length is 1-16 bytes.
        
        Args:
            plaintext: Unpadded plaintext bytes.
            
        Returns:
            Padded plaintext (length is multiple of 16).
        """
        # Calculate padding length: how many bytes needed to reach multiple of 16
        padding_length = self.IV_SIZE - (len(plaintext) % self.IV_SIZE)
        
        # Create padding: N bytes, each with value N
        padding = bytes([padding_length] * padding_length)
        
        return plaintext + padding

    def _unpad(self, padded_plaintext: bytes) -> bytes:
        """Remove PKCS7 padding from plaintext.
        
        Args:
            padded_plaintext: Padded plaintext bytes.
            
        Returns:
            Unpadded plaintext bytes.
            
        Raises:
            ValueError: If padding is invalid.
        """
        if len(padded_plaintext) == 0:
            raise ValueError("Cannot unpad empty plaintext")
        
        # The last byte indicates the padding length
        padding_length = padded_plaintext[-1]
        
        # Validate padding length
        if padding_length > self.IV_SIZE or padding_length == 0:
            raise ValueError(f"Invalid PKCS7 padding length: {padding_length}")
        
        # Validate that all padding bytes have the correct value
        for i in range(padding_length):
            if padded_plaintext[-(i + 1)] != padding_length:
                raise ValueError("Invalid PKCS7 padding: inconsistent padding bytes")
        
        # Remove padding
        return padded_plaintext[:-padding_length]

    def _update_key(self) -> None:
        """Update the current key using SHA-256 hash of the current key.
        
        After each message (encrypt or decrypt), derive the next key:
        new_key = SHA256(current_key)[:16]  (truncate to 128 bits)
        
        Also increment the key epoch counter.
        """
        hash_obj = hashlib.sha256(self._current_key)
        self._current_key = hash_obj.digest()[:self.AES_KEY_SIZE]
        self._key_epoch += 1

    def _encrypt_block(self, plaintext: bytes) -> Dict[str, bytes]:
        """Encrypt plaintext using AES-128-CBC with a random IV and HMAC authentication.
        
        Args:
            plaintext: Plaintext bytes to encrypt.
            
        Returns:
            Dictionary with keys:
                - 'iv': Random initialization vector (16 bytes)
                - 'ciphertext': Encrypted data
                - 'hmac': HMAC-SHA256 tag over (IV || ciphertext)
        """
        # Generate a random 16-byte IV
        iv = os.urandom(self.IV_SIZE)
        
        # Pad the plaintext to AES block size
        padded_plaintext = self._pad(plaintext)
        
        # Create AES-128-CBC cipher and encryptor
        cipher = Cipher(
            algorithms.AES(self._current_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Compute HMAC-SHA256 over IV || ciphertext
        message_to_auth = iv + ciphertext
        hmac_tag = hmac.new(
            self._current_key,
            message_to_auth,
            hashlib.sha256,
        ).digest()
        
        return {
            "iv": iv,
            "ciphertext": ciphertext,
            "hmac": hmac_tag,
        }

    def _decrypt_block(
        self,
        iv: bytes,
        ciphertext: bytes,
        hmac_tag: bytes,
    ) -> bytes:
        """Decrypt ciphertext using AES-128-CBC with HMAC verification.
        
        Verifies the HMAC tag before attempting decryption to prevent tampering.
        Uses constant-time comparison for HMAC verification.
        
        Args:
            iv: Initialization vector (16 bytes).
            ciphertext: Encrypted data.
            hmac_tag: HMAC-SHA256 tag to verify.
            
        Returns:
            Decrypted plaintext bytes (with padding removed).
            
        Raises:
            ValueError: If HMAC verification fails or decryption fails.
        """
        # Verify HMAC before decryption (constant-time comparison)
        message_to_auth = iv + ciphertext
        expected_hmac = hmac.new(
            self._current_key,
            message_to_auth,
            hashlib.sha256,
        ).digest()
        
        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(hmac_tag, expected_hmac):
            raise ValueError("HMAC verification failed: message may have been tampered with")
        
        # Create AES-128-CBC cipher and decryptor
        cipher = Cipher(
            algorithms.AES(self._current_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        plaintext = self._unpad(padded_plaintext)
        
        return plaintext

    def encrypt_message(self, plaintext: str) -> Dict[str, Any]:
        """Encrypt a plaintext message and return a JSON-serializable packet.
        
        Process:
        1. Convert plaintext string to UTF-8 bytes
        2. Encrypt using AES-128-CBC with random IV and HMAC tag
        3. Update the current key (SHA-256 of current key)
        4. Base64-encode binary fields for JSON serialization
        5. Return packet with epoch counter
        
        Args:
            plaintext: Plaintext message string.
            
        Returns:
            Dictionary with keys:
                - 'iv': Base64-encoded IV
                - 'ciphertext': Base64-encoded ciphertext
                - 'hmac': Base64-encoded HMAC tag
                - 'epoch': Current key epoch (for display)
        """
        try:
            # Convert plaintext string to UTF-8 bytes
            plaintext_bytes = plaintext.encode("utf-8")
            
            # Encrypt the plaintext
            encrypted = self._encrypt_block(plaintext_bytes)
            
            # Update the key for the next message
            self._update_key()
            
            # Base64-encode binary fields for JSON serialization
            packet = {
                "iv": base64.b64encode(encrypted["iv"]).decode("ascii"),
                "ciphertext": base64.b64encode(encrypted["ciphertext"]).decode("ascii"),
                "hmac": base64.b64encode(encrypted["hmac"]).decode("ascii"),
                "epoch": self._key_epoch,
            }
            
            return packet
        
        except Exception as e:
            # Return error message (should not happen with valid input)
            return {"error": f"Encryption failed: {str(e)}"}

    def decrypt_message(self, packet: Dict[str, Any]) -> str:
        """Decrypt a received packet and return the plaintext message.
        
        Process:
        1. Extract and base64-decode: IV, ciphertext, HMAC from packet
        2. Verify HMAC and decrypt using AES-128-CBC
        3. Update the current key (SHA-256 of current key)
        4. Decode UTF-8 bytes to plaintext string
        5. Return plaintext (or error message if decryption fails)
        
        Args:
            packet: Dictionary with keys 'iv', 'ciphertext', 'hmac' (base64-encoded).
            
        Returns:
            Plaintext message string, or error message string if decryption fails.
        """
        try:
            # Validate packet structure
            required_fields = ["iv", "ciphertext", "hmac"]
            for field in required_fields:
                if field not in packet:
                    return f"Error: Missing field '{field}' in packet"
            
            # Base64-decode binary fields
            try:
                iv = base64.b64decode(packet["iv"])
                ciphertext = base64.b64decode(packet["ciphertext"])
                hmac_tag = base64.b64decode(packet["hmac"])
            except Exception as e:
                return f"Error: Invalid base64 encoding in packet: {str(e)}"
            
            # Validate field sizes
            if len(iv) != self.IV_SIZE:
                return f"Error: Invalid IV size {len(iv)}, expected {self.IV_SIZE}"
            if len(hmac_tag) != self.HMAC_SIZE:
                return f"Error: Invalid HMAC size {len(hmac_tag)}, expected {self.HMAC_SIZE}"
            
            # Decrypt and verify HMAC
            plaintext_bytes = self._decrypt_block(iv, ciphertext, hmac_tag)
            
            # Update the key for the next message
            self._update_key()
            
            # Decode UTF-8 bytes to plaintext string
            plaintext = plaintext_bytes.decode("utf-8")
            
            return plaintext
        
        except ValueError as e:
            # HMAC verification failed or padding error
            return f"Error: {str(e)}"
        except Exception as e:
            # Other decryption errors
            return f"Error: Decryption failed: {str(e)}"

    def current_key_epoch(self) -> int:
        """Return the current key epoch counter.
        
        The epoch counter increments after each message (send or receive).
        Used by the GUI to display the current key update state.
        
        Returns:
            Current key epoch as integer.
        """
        return self._key_epoch