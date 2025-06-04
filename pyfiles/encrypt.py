from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import argon2
import os
import time
import hashlib


class AESFileEncryptor:
    """AES-256 file encryptor and decryptor using Argon2ID-based key derivation."""

    def __init__(self):
        pass

    def _derive_key(self, salt: bytes, password: str) -> bytes:
        """Derive a 256-bit key from the password and salt using Argon2ID."""
        # These parameters should match your security requirements
        return argon2.low_level.hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=8,
            memory_cost=524288,  # 512 MiB
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )

    def sha3_512_hash(self, filepath: str) -> str:
        """Compute the SHA3-512 hash of a file."""
        hasher = hashlib.sha3_512()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def encrypt_file(self, password: str, input_path: str, output_path: str):
        """Encrypt a file using AES-256-CBC, storing salt, IV, and SHA3-512 hash at the start."""
        salt = os.urandom(16)
        key = self._derive_key(salt, password)
        iv = os.urandom(16)
        cipher = Cipher(
            algorithm=algorithms.AES(key), mode=modes.CBC(iv), backend=default_backend()
        )
        file_hash = self.sha3_512_hash(input_path)
        print(f"SHA3-512 hash of {input_path}: {file_hash:.12s}...")
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        with open(input_path, "rb") as f:
            plaintext = f.read()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_path, "wb") as f:
            f.write(salt + iv + ciphertext + bytes.fromhex(file_hash))  # Append hash

    def decrypt_file(self, password: str, input_path: str, output_path: str):
        """Decrypt a file previously encrypted with this class and verify integrity.

        Raises:
            ValueError: If the password is incorrect, the file is corrupted, or the hash does not match.
        """
        try:
            with open(input_path, "rb") as f:
                data = f.read()
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:-64]
            # The last 64 bytes are the SHA3-512 hash (512 bits = 64 bytes)
            file_hash_bytes = data[-64:]
            key = self._derive_key(salt=salt, password=password)
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            with open(output_path, "wb") as f:
                f.write(plaintext)

            # Verify hash
            computed_hash = hashlib.sha3_512(plaintext).digest()
            print(f"Computed hash: {computed_hash.hex():.12s}...")
            if computed_hash == file_hash_bytes:
                print(f"File integrity check passed: SHA3-512 hash matches.")
            else:
                raise ValueError(
                    "File integrity check failed: SHA3-512 hash does not match."
                )

        except (ValueError, Exception) as e:
            raise ValueError(
                "Decryption failed: the password may be incorrect, the file may be corrupted, or the hash does not match."
            ) from e


if __name__ == "__main__":
    fe = AESFileEncryptor()
    # Remove the encrypted and decrypted files if they exist
    for file_path in [
        r"./pyfiles/.testing/pyinstall_help.txt.bin",
        r"./pyfiles/.testing/pyinstalled_help.txt",
    ]:
        try:
            os.remove(file_path)
            print(f"Removed file: {file_path}")
        except FileNotFoundError:
            print(f"File not found or doesn't exist: {file_path}")
            pass

    start_encrypt = time.time()
    fe.encrypt_file(
        password=r"Testing",
        input_path=r"./pyfiles/.testing/pyinstall_help.txt",
        output_path=r"./pyfiles/.testing/pyinstall_help.txt.bin",
    )
    end_encrypt = time.time()
    print(f"Encryption took {end_encrypt - start_encrypt:.3f} seconds.")

    start_decrypt = time.time()
    fe.decrypt_file(
        password=r"Testing",
        input_path=r"./pyfiles/.testing/pyinstall_help.txt.bin",
        output_path=r"./pyfiles/.testing/pyinstalled_help.txt",
    )
    end_decrypt = time.time()
    print(f"Decryption took {end_decrypt - start_decrypt:.3f} seconds.")
