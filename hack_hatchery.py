#!/usr/bin/env python3
import os
import uuid
import argparse
import sqlite3
import random
from flask import Flask, request
from cryptography.fernet import Fernet

# Generate a unique flag
def generate_flag():
    return f"CTF{{{str(uuid.uuid4())[:8]}}}"

# Save the flag to a file
def save_flag(challenge_dir, flag):
    try:
        with open(f"{challenge_dir}/flag.txt", "w") as f:
            f.write(flag)
    except IOError as e:
        print(f"Error saving flag: {e}")
        sys.exit(1)

# Create a vulnerable Flask web challenge
def create_web_challenge(challenge_dir, flag, difficulty):
    app_code = f"""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('input')
    conn = sqlite3.connect('{challenge_dir}/database.db')
    cursor = conn.cursor()

    # Different vulnerabilities based on difficulty
    if "{difficulty}" == "easy":
        query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    elif "{difficulty}" == "medium":
        query = f"SELECT * FROM users WHERE name = '{{user_input}}' --"
    else:  # hard
        query = f"SELECT * FROM users WHERE name = '{{user_input}}' AND password = 'secret'"

    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
"""

    # Write the Flask app to a file
    try:
        with open(f"{challenge_dir}/app.py", "w") as f:
            f.write(app_code)
    except IOError as e:
        print(f"Error writing Flask app: {e}")
        sys.exit(1)

    # Create SQLite database
    try:
        conn = sqlite3.connect(f"{challenge_dir}/database.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (name TEXT, password TEXT)")
        cursor.execute(f"INSERT INTO users (name, password) VALUES ('admin', '{flag}')")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Error creating database: {e}")
        sys.exit(1)

    print(f"Web challenge created in {challenge_dir}. Start the server with: python3 {challenge_dir}/app.py")

# Create a cryptography challenge
def create_crypto_challenge(challenge_dir, flag, difficulty):
    encryption_key = random.randint(1, 25)  # Shift for Caesar cipher

    if difficulty == "easy":
        encrypted_flag = "".join(chr(((ord(c) - 65 + encryption_key) % 26) + 65) if c.isalpha() else c for c in flag.upper())
        hint = "The flag is encrypted using a Caesar cipher. Try shifting the letters!"
    elif difficulty == "medium":
        encrypted_flag = flag.encode("utf-8").hex()  # Hex encoding
        hint = "The flag is encoded in hexadecimal. Decode it to find the flag!"
    else:  # hard
        encrypted_flag = "".join(chr(ord(c) ^ encryption_key) for c in flag)  # XOR encryption
        hint = "The flag is encrypted using XOR. Find the key and decrypt it!"

    try:
        with open(f"{challenge_dir}/challenge.txt", "w") as f:
            f.write(f"Decrypt this: {encrypted_flag}\n")

        with open(f"{challenge_dir}/README.txt", "w") as f:
            f.write(f"Crypto Challenge (Difficulty: {difficulty})\n\n{hint}\n")
    except IOError as e:
        print(f"Error writing crypto challenge files: {e}")
        sys.exit(1)

    print(f"Crypto challenge created in {challenge_dir}. Check challenge.txt for details.")

# Create a forensics challenge
def create_forensics_challenge(challenge_dir, flag):
    try:
        with open(f"{challenge_dir}/hidden_data.txt", "w") as f:
            f.write(flag)

        os.system(f"zip -q {challenge_dir}/challenge.zip {challenge_dir}/hidden_data.txt")
        os.remove(f"{challenge_dir}/hidden_data.txt")

        with open(f"{challenge_dir}/README.txt", "w") as f:
            f.write("Forensics Challenge\n\n")
            f.write("A suspicious ZIP file was found. Extract its contents to find the flag.\n")
    except IOError as e:
        print(f"Error creating forensics challenge: {e}")
        sys.exit(1)

    print(f"Forensics challenge created in {challenge_dir}. Find the flag inside challenge.zip.")

# Print challenge summary
def print_summary(challenge_dir, challenge_type, difficulty):
    print("\n=== Challenge Summary ===")
    print(f"Type: {challenge_type}")
    print(f"Difficulty: {difficulty}")
    print(f"Location: {challenge_dir}")
    if challenge_type == "web":
        print("To solve: Start the Flask server and exploit the vulnerability.")
    elif challenge_type == "crypto":
        print("To solve: Decrypt the message in challenge.txt.")
    elif challenge_type == "forensics":
        print("To solve: Extract the ZIP file and find the hidden flag.")
    print("========================\n")

# Main function
def main():
    parser = argparse.ArgumentParser(description="CTF Challenge Generator")
    parser.add_argument('--type', choices=['web', 'crypto', 'forensics'], required=True, help="Type of challenge to generate")
    parser.add_argument('--difficulty', choices=['easy', 'medium', 'hard'], default='easy', help="Challenge difficulty level")
    parser.add_argument('--output', default='challenges', help="Output directory for challenges")
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    if not os.path.exists(args.output):
        os.makedirs(args.output)

    # Generate a unique challenge directory
    challenge_dir = os.path.join(args.output, f"challenge_{str(uuid.uuid4())[:8]}")
    os.makedirs(challenge_dir)

    # Generate a flag
    flag = generate_flag()

    # Save the flag (hidden from users)
    save_flag(challenge_dir, flag)

    # Generate the selected challenge type
    if args.type == 'web':
        create_web_challenge(challenge_dir, flag, args.difficulty)
    elif args.type == 'crypto':
        create_crypto_challenge(challenge_dir, flag, args.difficulty)
    elif args.type == 'forensics':
        create_forensics_challenge(challenge_dir, flag)

    # Print challenge summary
    print_summary(challenge_dir, args.type, args.difficulty)

if __name__ == '__main__':
    main()
