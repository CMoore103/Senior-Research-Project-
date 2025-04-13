import random
import string
import nltk
nltk.download('words')
from nltk.corpus import words

#Amount of Passwords to generate
NUM_PASSWORDS = 100

#Define character sets
lower_case = string.ascii_lowercase
upper_case = string.ascii_uppercase
digits = string.digits
symbols = "!@#$%^&*()_+-=[]{};:,<>./?"

common_words = [word.lower() for word in words.words() if 3 <= len(word) <= 6]


def save_passwords(filename, passwords):
    with open(filename, "w") as f:
        for pswd in passwords:
            f.write(pswd + "\n")
    print("Passwords saved to", filename)


def generate_weak_passwords():
    passwords = []
    for i in range(NUM_PASSWORDS):
        length = 6
        chars = lower_case + digits
        pwd = "".join(random.choices(chars, k=length))
        passwords.append(pwd)
    return passwords


def generate_medium_passwords():
    passwords = []
    for i in range(NUM_PASSWORDS):
        length = 8
        word = random.choice(common_words)
        word = word.capitalize()

        digit = random.randint(10,99)
        end_char = random.choice(lower_case + digits)
        pwd = word + str(digit) + end_char
         # If password exceeds 8 characters, trim it
        if len(pwd) > 8:
            pwd = pwd[:8]
        
        # If password is shorter than 8 characters, pad it
        if len(pwd) < 8:
            # Add random characters to pad it to 8
            pwd += random.choice(string.ascii_letters + string.digits) * (8 - len(pwd))

        passwords.append(pwd)
    return passwords


def generate_strong_passwords():
    passwords = []
    for i in range(NUM_PASSWORDS):
        length = 16
        pwd = [ random.choice(upper_case) ,
            random.choice(lower_case),
            random.choice(digits) ,
            random.choice(symbols)]
        

        pwd += random.choices(upper_case + lower_case + symbols + digits, k=length - 4)
        random.shuffle(pwd)
        passwords.append(''.join(pwd))
    return passwords


weak_pwds = generate_weak_passwords()
medium_pwds = generate_medium_passwords()
strong_pwds = generate_strong_passwords()

save_passwords("weak_passwords.txt", weak_pwds)
save_passwords("medium_passwords.txt", medium_pwds)
save_passwords("strong_passwords.txt", strong_pwds)




