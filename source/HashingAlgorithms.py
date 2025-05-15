import hashlib
import bcrypt
import os
from argon2 import PasswordHasher
import time
import base64
import binascii


# Initialize Argon2 hasher
ph = PasswordHasher()

def read_passwords_from_file(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def hash_scrypt(password):
    # Generate a random 16-byte salt
    salt = os.urandom(16)

    # Scrypt parameters
    N = 1024  # CPU/memory cost factor
    r = 1     # Block size
    p = 1     # Parallelization factor
    dklen = 32  # Length of the derived key

    # Generate the scrypt-derived key
    key = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p, dklen=dklen)

    # Convert salt and key to base64
    salt_b64 = base64.b64encode(salt).decode('utf-8').rstrip('=')
    key_b64 = base64.b64encode(key).decode('utf-8').rstrip('=')

    # Convert N to log2(N) for Hashcat compatibility
    ln = int(N).bit_length() - 1

    # Return the properly formatted scrypt hash
    return f"$scrypt$ln={ln},r={r},p={p}${salt_b64}${key_b64}"


def hash_argon2(password):
    return ph.hash(password)

def write_hashes_to_file(passwords, algorithm_name, hash_func, strength):
    # File for hashes
    hash_filename = f"{strength}_{algorithm_name}_hashes.txt"
    # File for times
    time_filename = f"{strength}_{algorithm_name}_times.txt"

    with open(hash_filename, 'w') as hash_file, open(time_filename, 'w') as time_file:
        for pwd in passwords:
            try:
                # Measure the start time
                start_time = time.perf_counter()

                # Generate the hash
                hash_val = hash_func(pwd)

                # Measure the end time
                end_time = time.perf_counter()

                # Calculate the time taken
                time_taken = end_time - start_time

                # Write the hash to the hash file
                hash_file.write(f"{hash_val}\n")

                # Write the time taken to the time file
                time_file.write(f"{time_taken:.6f} seconds\n")
            except Exception as e:
                print(f"[{algorithm_name.upper()}] Failed to hash '{pwd}': {e}")

def main():
    strengths = ['weak_passwords', 'medium_passwords', 'strong_passwords']
    hash_algorithms = {
        'md5': hash_md5,
        'bcrypt': hash_bcrypt,
        'scrypt': hash_scrypt,
        'argon2': hash_argon2
    }

    for strength in strengths:
        pwd_file = f"{strength}.txt"
        passwords = read_passwords_from_file(pwd_file)
        for algo_name, hash_func in hash_algorithms.items():
            write_hashes_to_file(passwords, algo_name, hash_func, strength)

if __name__ == "__main__":
    main()




