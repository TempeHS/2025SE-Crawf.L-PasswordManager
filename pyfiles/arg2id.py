import argon2


class Argon2IDHasher:
    def __init__(
        self, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16
    ):
        """
        Initialises the Argon2IDHasher with configurable parameters.

        Args:
            time_cost (int, optional): _description_. Defaults to 2.
            memory_cost (int, optional): _description_. Defaults to 102400.
            parallelism (int, optional): _description_. Defaults to 8.
            hash_len (int, optional): _description_. Defaults to 32.
            salt_len (int, optional): _description_. Defaults to 16.
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
    print(f"Does the password match?: {hasher.verify(hashed, "mysecretpassword")}")
