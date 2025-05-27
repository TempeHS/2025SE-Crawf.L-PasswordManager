import argon2

TIME_COST_DEFAULT = 2
MEMORY_COST_DEFAULT = 102400
PARALLELISM_DEFAULT = 8
HASH_LEN_DEFAULT = 32
SALT_LEN_DEFAULT = 16


def MiB_to_KiB(mebi):
    kibi = mebi * 1024
    return kibi


def GiB_to_KiB(gibi):
    kibi = gibi * (1024**2)
    return kibi


class Argon2IDHasher:

    def __init__(
        self,
        time_cost: int = TIME_COST_DEFAULT,
        memory_cost: int = MEMORY_COST_DEFAULT,
        parallelism: int = PARALLELISM_DEFAULT,
        hash_len: int = HASH_LEN_DEFAULT,
        salt_len: int = SALT_LEN_DEFAULT,
    ):
        """
        Initialises the Argon2IDHasher with configurable parameters.

        Args:
            time_cost (int): The number of iterations to perform when hashing. Higher values increase computation time and security.
                _Default_: 2 iterations
            memory_cost (int): The amount of memory (in kibibytes) to use during hashing. Higher values increase security.
                _Default_: 100 MiB
            parallelism (int): The number of parallel threads to use for hashing.
                _Default_: 8 threads
            hash_len (int): The desired length of the resulting hash in bytes.
                _Default_: 32 bytes
            salt_len (int): The length of the random salt to use in bytes.
                _Default_: 16 bytes

        Sets up the internal Argon2ID PasswordHasher instance with the specified parameters.
        """

        self.ph = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
            type=argon2.low_level.Type.ID,
        )

    def hash(self, password: str) -> str:
        """
        Hashes a password using Argon2ID.
        Args:
            password (str): The password to hash.
        Returns:
            str: The hashed password.
        """
        return self.ph.hash(password)

    def verify(self, hash: str, password: str) -> bool:
        """
        Verifies if the provided password matches the given Argon2ID hash.
        Args:
            hash (str): The Argon2ID hash to verify against.
            password (str): The plaintext password to check.

        Returns:
            bool: True if the password matches the hash, False otherwise.
        """

        try:
            return self.ph.verify(hash, password)
        except argon2.exceptions.VerifyMismatchError:
            return False


if __name__ == "__main__":
    # Example usage
    hasher = Argon2IDHasher()
    hashed = hasher.hash("mysecretpassword")
    print(f"Hashed password: {hashed}")
    print(f"Does the password match?: {hasher.verify(hashed, 'mysecretpassword')}")
