import argon2

def hash_password(password):
    """
    Hashes a password using Argon2.
    """
    # Choose parameters
    time_cost = 16  # The number of iterations
    memory_cost = 2**16  # Memory cost in kibibytes
    parallelism = 1  # Number of threads to use

    # Hash password
    hasher = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
    hashed_password = hasher.hash(password)

    return hashed_password

def verify_password(hashed_password, password):
    """
    Verifies a password against its hashed version.
    """
    try:
        # Verify password
        argon2.PasswordHasher().verify(hashed_password, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

# Example usage
password = input("Enter Password: ")
hashed_password = hash_password(password)
print("Hashed password:", hashed_password)

# Verify password
password_to_check = "Password123"
if verify_password(hashed_password, password_to_check):
    print("Password is correct.")
else:
    print("Password is incorrect.")