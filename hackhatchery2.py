#!/usr/bin/env python3
import os
import uuid
import argparse
import sqlite3
import random
import base64
import binascii
from flask import Flask, request
from pathlib import Path
from enum import Enum, auto
from typing import Optional, Dict, Any
import hashlib
from cryptography.fernet import Fernet  # For better crypto challenges

class ChallengeType(Enum):
    WEB = auto()
    CRYPTO = auto()
    FORENSICS = auto()

class WebChallengeType(Enum):
    SQLI = auto()
    XSS = auto()
    LFI = auto()
    BRUTE_FORCE = auto()

class CryptoChallengeType(Enum):
    BASE64 = auto()
    ROT13 = auto()
    VIGENERE = auto()
    XOR = auto()
    AES = auto()
    RSA_SIMPLIFIED = auto()

class ForensicsChallengeType(Enum):
    STEGANOGRAPHY = auto()
    EXIF_METADATA = auto()
    PCAP_ANALYSIS = auto()
    BINARY_FILE = auto()

class ChallengeGenerator:
    def __init__(self):
        self.app = Flask(__name__)
        
    def generate_flag(self) -> str:
        """Generate a unique CTF flag"""
        return f"CTF{{{str(uuid.uuid4())}}}"

    def create_challenge_directory(self, base_path: str) -> Path:
        """Create a directory for the challenge"""
        challenge_dir = Path(base_path) / f"challenge_{str(uuid.uuid4())[:8]}"
        challenge_dir.mkdir(parents=True, exist_ok=True)
        return challenge_dir

    def save_flag(self, challenge_dir: Path, flag: str) -> None:
        """Save the flag to a file"""
        try:
            with open(challenge_dir / "flag.txt", "w") as f:
                f.write(flag)
        except IOError as e:
            print(f"Error saving flag: {e}")
            raise

    def generate_web_challenge(self, challenge_dir: Path, flag: str) -> Dict[str, Any]:
        """Generate a random web challenge"""
        challenge_type = random.choice(list(WebChallengeType))
        db_path = challenge_dir / "database.db"
        
        # Setup database
        self._setup_database(db_path, flag)
        
        # Generate challenge files
        return self._generate_web_challenge_files(challenge_type, challenge_dir, db_path, flag)

    def _setup_database(self, db_path: Path, flag: str) -> None:
        """Setup SQLite database for web challenges"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, password TEXT)")
        cursor.execute("INSERT INTO users VALUES ('admin', ?)", (flag,))
        cursor.execute("INSERT INTO users VALUES ('guest', 'password123')")
        conn.commit()
        conn.close()

    def _generate_web_challenge_files(self, challenge_type: WebChallengeType, 
                                    challenge_dir: Path, db_path: Path, flag: str) -> Dict[str, Any]:
        """Generate files for specific web challenge type"""
        db_path_relative = db_path.relative_to(challenge_dir)
        
        challenge_info = {
            "type": challenge_type.name.replace("_", " ").title(),
            "hint": "",
            "files": ["app.py", "database.db"],
            "setup_commands": ["pip install flask"],
            "run_command": "python app.py"
        }

        if challenge_type == WebChallengeType.SQLI:
            challenge_info["hint"] = "The web app has an SQL Injection vulnerability. Try injecting a malicious query!"
            self._create_sqli_challenge(challenge_dir, db_path_relative)
            
        elif challenge_type == WebChallengeType.XSS:
            challenge_info["hint"] = "User input is not sanitized. Try injecting a script!"
            self._create_xss_challenge(challenge_dir)
            
        elif challenge_type == WebChallengeType.LFI:
            challenge_info["hint"] = "A file path is directly used in `open()`. Can you read sensitive files?"
            self._create_lfi_challenge(challenge_dir)
            
        elif challenge_type == WebChallengeType.BRUTE_FORCE:
            challenge_info["hint"] = "Brute-force the admin password!"
            self._create_brute_force_challenge(challenge_dir, flag)
            
        # Create common files
        self._create_web_common_files(challenge_dir)
        return challenge_info

    def _create_sqli_challenge(self, challenge_dir: Path, db_path: Path) -> None:
        """Create SQL injection challenge"""
        app_code = f"""from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('input', '')
    conn = sqlite3.connect('{db_path}')
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT * FROM users WHERE name = '{{user_input}}'")
        result = cursor.fetchall()
    except Exception as e:
        return str(e)
    finally:
        conn.close()
    return str(result)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
"""
        with open(challenge_dir / "app.py", "w") as f:
            f.write(app_code)

    def _create_xss_challenge(self, challenge_dir: Path) -> None:
        """Create XSS challenge"""
        app_code = """from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('input', '')
    return f'''
        <h2>XSS Challenge</h2>
        <form>
            <input type="text" name="input" placeholder="Enter your name">
            <button type="submit">Submit</button>
        </form>
        <div>Welcome {user_input}</div>
    '''

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
"""
        with open(challenge_dir / "app.py", "w") as f:
            f.write(app_code)

    def _create_lfi_challenge(self, challenge_dir: Path) -> None:
        """Create LFI challenge with safety restrictions"""
        app_code = f"""from flask import Flask, request
import os

app = Flask(__name__)

# Safe base directory restriction
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    file = request.args.get('file', 'index.html')
    # Prevent directory traversal
    file_path = os.path.join(BASE_DIR, os.path.basename(file))
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    except:
        return "Error reading file"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
"""
        with open(challenge_dir / "app.py", "w") as f:
            f.write(app_code)
        
        # Create sample files
        with open(challenge_dir / "index.html", "w") as f:
            f.write("<h1>Welcome to the challenge!</h1>")

    def _create_brute_force_challenge(self, challenge_dir: Path, flag: str) -> None:
        """Create brute force challenge"""
        app_code = f"""from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <form action="/login" method="POST">
            <input type="text" name="user" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user', '')
    password = request.form.get('password', '')
    if user == 'admin' and password == '{flag}':
        return 'Welcome, admin! Here is your flag: {flag}'
    return 'Invalid login'

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
"""
        with open(challenge_dir / "app.py", "w") as f:
            f.write(app_code)

    def _create_web_common_files(self, challenge_dir: Path) -> None:
        """Create files common to all web challenges"""
        with open(challenge_dir / "README.md", "w") as f:
            f.write("# Web Challenge\n\nFind and exploit the vulnerability to get the flag!\n")

    def generate_crypto_challenge(self, challenge_dir: Path, flag: str) -> Dict[str, Any]:
        """Generate a random crypto challenge"""
        challenge_type = random.choice(list(CryptoChallengeType))
        challenge_info = {
            "type": challenge_type.name.replace("_", " ").title(),
            "hint": "",
            "files": ["challenge.txt"],
            "solution_script": None
        }

        if challenge_type == CryptoChallengeType.BASE64:
            encrypted_flag = base64.b64encode(flag.encode()).decode()
            challenge_info["hint"] = "This flag is encoded using Base64."
            challenge_info["solution_script"] = "base64.b64decode(encrypted_flag).decode()"
            
        elif challenge_type == CryptoChallengeType.ROT13:
            encrypted_flag = flag.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
            challenge_info["hint"] = "The flag is ROT13 encoded."
            challenge_info["solution_script"] = "encrypted_flag.translate(str.maketrans(\n    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',\n    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'\n))"
            
        elif challenge_type == CryptoChallengeType.VIGENERE:
            key = "CTFKEY"
            encrypted_flag = "".join(chr(((ord(c) - 65 + ord(key[i % len(key)])) % 26 + 65)) if c.isalpha() else c
        for i, c in enumerate(flag.upper()))
    
            challenge_info["hint"] = f"The flag is encrypted using a Vigenère cipher. Key: {key}"
    
            challenge_info["solution_script"] = f"""def vigenere_decrypt(ciphertext, key):
    return ''.join(
        chr(((ord(c) - 65 - ord(key[i % len(key)])) % 26 + 65)) if c.isalpha() else c
        for i, c in enumerate(ciphertext)
    )
vigenere_decrypt(encrypted_flag, '{key}')"""

            
        elif challenge_type == CryptoChallengeType.XOR:
            key = random.randint(1, 255)
            encrypted_flag = "".join(chr(ord(c) ^ key) for c in flag)
            challenge_info["hint"] = f"The flag is XOR-encrypted. Key is an integer between 1-255."
            challenge_info["solution_script"] = f"""def xor_decrypt(ciphertext, key):
    return ''.join(chr(ord(c) ^ {key}) for c in ciphertext)
xor_decrypt(encrypted_flag, {key})"""
            
        elif challenge_type == CryptoChallengeType.AES:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted_flag = fernet.encrypt(flag.encode()).decode()
            challenge_info["hint"] = "The flag is AES encrypted (Fernet implementation)."
            challenge_info["solution_script"] = f"""from cryptography.fernet import Fernet
fernet = Fernet({key})
fernet.decrypt(encrypted_flag.encode()).decode()"""
            # Save the key in a separate file
            with open(challenge_dir / "key.txt", "w") as f:
                f.write(key.decode())
            challenge_info["files"].append("key.txt")
            
        elif challenge_type == CryptoChallengeType.RSA_SIMPLIFIED:
            # Simplified RSA-like challenge
            encrypted_flag = binascii.hexlify(flag.encode()).decode()
            challenge_info["hint"] = "The flag is hex-encoded (simplified RSA challenge)."
            challenge_info["solution_script"] = "bytes.fromhex(encrypted_flag).decode()"

        with open(challenge_dir / "challenge.txt", "w") as f:
            f.write(f"Decrypt this: {encrypted_flag}\n")

        with open(challenge_dir / "README.md", "w") as f:
            f.write(f"# Crypto Challenge: {challenge_info['type']}\n\n")
            f.write(f"**Hint**: {challenge_info['hint']}\n\n")
            if challenge_info["solution_script"]:
                f.write("## Solution Script\n```python\n")
                f.write(challenge_info["solution_script"])
                f.write("\n```\n")

        return challenge_info
        
    def generate_forensics_challenge(self, challenge_dir: Path, flag: str) -> Dict[str, Any]:
        """Generate a random forensics challenge"""
        challenge_type = random.choice(list(ForensicsChallengeType))
        challenge_info = {
            "type": challenge_type.name.replace("_", " ").title(),
            "hint": "",
            "files": [],
            "tools": []
        }

        if challenge_type == ForensicsChallengeType.STEGANOGRAPHY:
            # Create a fake image with hidden flag
            with open(challenge_dir / "image.jpg", "wb") as f:
                f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF")  # JPEG header
                f.write(b"\x00" * 100)  # Padding
                f.write(f"FLAG: {flag}".encode())
                f.write(b"\x00" * 100)  # More padding
                f.write(b"\xff\xd9")  # JPEG footer
            challenge_info["hint"] = "The flag is hidden inside an image. Try using steghide or binwalk."
            challenge_info["files"].append("image.jpg")
            challenge_info["tools"].extend(["steghide", "binwalk", "xxd"])
            
        elif challenge_type == ForensicsChallengeType.EXIF_METADATA:
            # Create image with EXIF metadata
            with open(challenge_dir / "photo.jpg", "wb") as f:
                f.write(b"\xff\xd8\xff\xe1")  # JPEG header with EXIF
                f.write(b"Exif\x00\x00")  # EXIF header
                f.write(b"\x00" * 50)
                f.write(f"FLAG: {flag}".encode())
                f.write(b"\x00" * 50)
                f.write(b"\xff\xd9")  # JPEG footer
            challenge_info["hint"] = "Check the image metadata!"
            challenge_info["files"].append("photo.jpg")
            challenge_info["tools"].append("exiftool")
            
        elif challenge_type == ForensicsChallengeType.PCAP_ANALYSIS:
            # Create fake PCAP with flag
            with open(challenge_dir / "traffic.pcap", "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1")  # PCAP magic number
                f.write(b"\x00" * 20)  # PCAP header
                f.write(f"FLAG: {flag}".encode())
            challenge_info["hint"] = "Analyze the network traffic."
            challenge_info["files"].append("traffic.pcap")
            challenge_info["tools"].extend(["wireshark", "tshark"])
            
        elif challenge_type == ForensicsChallengeType.BINARY_FILE:
            # Create binary file with flag
            with open(challenge_dir / "data.bin", "wb") as f:
                f.write(b"\x7fELF")  # ELF magic number
                f.write(b"\x00" * 50)
                f.write(flag.encode())
                f.write(b"\x00" * 50)
            challenge_info["hint"] = "Analyze the binary file for hidden data."
            challenge_info["files"].append("data.bin")
            challenge_info["tools"].extend(["strings", "xxd", "hexdump"])

        with open(challenge_dir / "README.md", "w") as f:
            f.write(f"# Forensics Challenge: {challenge_info['type']}\n\n")
            f.write(f"**Hint**: {challenge_info['hint']}\n\n")
            if challenge_info["tools"]:
                f.write("**Suggested Tools**: " + ", ".join(challenge_info["tools"]) + "\n")

        return challenge_info

    def generate_challenge(self, challenge_type: ChallengeType, output_dir: str) -> Dict[str, Any]:
        """Main method to generate a challenge"""
        challenge_dir = self.create_challenge_directory(output_dir)
        flag = self.generate_flag()
        self.save_flag(challenge_dir, flag)

        challenge_info = {
            "flag": flag,
            "directory": str(challenge_dir),
            "type": challenge_type.name.lower()
        }

        if challenge_type == ChallengeType.WEB:
            web_info = self.generate_web_challenge(challenge_dir, flag)
            challenge_info.update(web_info)
            
        elif challenge_type == ChallengeType.CRYPTO:
            crypto_info = self.generate_crypto_challenge(challenge_dir, flag)
            challenge_info.update(crypto_info)
            
        elif challenge_type == ChallengeType.FORENSICS:
            forensics_info = self.generate_forensics_challenge(challenge_dir, flag)
            challenge_info.update(forensics_info)

        # Create solution file
        with open(challenge_dir / "SOLUTION.md", "w") as f:
            f.write(f"# Solution\n\nFlag: `{flag}`\n\n")
            f.write("## How to solve:\n")
            f.write(f"1. {challenge_info['hint']}\n")
            if "solution_script" in challenge_info:
                f.write("\nSolution script:\n```python\n")
                f.write(challenge_info["solution_script"])
                f.write("\n```\n")

        return challenge_info

def main():
    parser = argparse.ArgumentParser(description="CTF Challenge Generator")
    parser.add_argument('--type', choices=['web', 'crypto', 'forensics'], 
                       required=True, help="Type of challenge to generate")
    parser.add_argument('--output', default='challenges', 
                       help="Output directory for challenges")
    args = parser.parse_args()

    generator = ChallengeGenerator()
    
    try:
        challenge_type = {
            'web': ChallengeType.WEB,
            'crypto': ChallengeType.CRYPTO,
            'forensics': ChallengeType.FORENSICS
        }[args.type]
        
        result = generator.generate_challenge(challenge_type, args.output)
        
        print("==== Challenge successfully created ====\n")
        print(f"Files Directory: {result['directory']}")
        if challenge_type == ChallengeType.WEB:
            
            print(f"\nTo run the web challenge:")
            print(f"{result['directory']} && python app.py")
        
    except Exception as e:
        print(f"Error generating challenge: {e}")
        exit(1)

if __name__ == '__main__':
    main()
