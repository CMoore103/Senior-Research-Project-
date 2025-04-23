import os
import subprocess

def choose_attack_mode():
    print("Select the attack mode:")
    print("1. Dictionary attack (wordlist)")
    print("2. Brute-force attack")
    print("3. Hybrid attack (dictionary + mask)")
    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == "1":
        wordlist = input("Enter path to wordlist (default: rockyou.txt): ").strip()
        return {"mode": 0, "wordlist": wordlist if wordlist else "rockyou.txt"}
    elif choice == "2":
        mask = input("Enter mask (e.g., ?a?a?a?a?a?a): ").strip()
        return {"mode": 3, "mask": mask}
    elif choice == "3":
        wordlist = input("Enter path to wordlist: ").strip()
        mask = input("Enter mask to append (e.g., ?d?d): ").strip()
        return {"mode": 6, "wordlist": wordlist if wordlist else "rockyou.txt", "mask": mask}
    else:
        print("Invalid choice")
        return {"mode": 0, "wordlist": "rockyou.txt"}

def get_hashcat_mode(algorithm):
    modes = {
        'md5': 0,
        'bcrypt': 3200,
        'scrypt': 8900,
        'argon2': 13000
    }
    return modes.get(algorithm)

def run_hashcat(hash_file, algorithm, attack_config):
    hashcat_mode = get_hashcat_mode(algorithm)
    if hashcat_mode is None:
        print(f"Unsupported algorithm: {algorithm}")
        return

    cmd = [
        "hashcat",
        "-m", str(hashcat_mode),
        "-a", str(attack_config["mode"]),
        hash_file
    ]

    if attack_config["mode"] == 0:
        cmd.append(attack_config["wordlist"])
    elif attack_config["mode"] == 3:
        cmd.append(attack_config["mask"])
    elif attack_config["mode"] == 6:
        cmd.extend([attack_config["wordlist"], attack_config["mask"]])

    cmd.extend(["--opencl-device-types", "2"])  # Use GPU
    cmd.extend(["--runtime", "18000"])
    print("Running:", " ".join(cmd))
    subprocess.run(cmd)

def main():
    algorithms = {
        '1' : "MD5",
        '2' : "bcrypt", 
        '3' : "scrypt", 
        '4' : "argon2"
    }

    print("Select the algorithm to use:")
    print("1. MD5")
    print("2. Bcrypt")
    print("3. Scrypt")
    print("4. Argon2")
    algo_choice = input("Enter your choice(1/2/3/4): ").strip()
    if algo_choice not in algorithms:
        print("Invalid choice")
        return
    algorithm = algorithms[algo_choice].lower()

    attack_config = choose_attack_mode()
    hash_file = input("Enter the file name containing the hashes to crack: ")
    hash_file = os.path.abspath(hash_file)
    print(hash_file)
    if not os.path.exists(hash_file):
        print("File not found")
        return
    
    hashcat_path = input("Enter the path to Hashcat executable")
    if not os.path.exists(hashcat_path):
        print("Hashcat path not found")
        return
    os.chdir(hashcat_path)

    print("\nStarting automated cracking with Hashcat...\n")
    run_hashcat(hash_file, algorithm, attack_config)
          
if __name__ == "__main__":
    main()