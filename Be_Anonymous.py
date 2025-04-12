import os
import sys
import platform
import subprocess
import requests
import time
import json
import shlex
import signal
import re
from cryptography.fernet import Fernet, InvalidToken
from threading import Thread

# Verified if windows, if windows close windows
if platform.system() == "Windows":
    sys.exit()

# Define the key file name
KEY_FILE = "encryption_key.key"

# Function to generate a new encryption key
def generate_key():
    return Fernet.generate_key()

# Function to save the encryption key to a file
def save_key_to_file(key):
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

# Function to load the encryption key from a file
def load_key_from_file():
    try:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
            # Validate the key by trying to create a Fernet instance
            Fernet(key)
            return key
    except (FileNotFoundError, InvalidToken):
        print("Invalid or missing encryption key. Generating a new one...")
        key = generate_key()
        save_key_to_file(key)
        return key

# Load or generate encryption key
key = load_key_from_file()

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Function to decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    try:
        return fernet.decrypt(data).decode()
    except InvalidToken:
        print("Invalid encryption key or corrupted data!")
        return None

# Function to check if a command is installed
def is_command_installed(command):
    try:
        subprocess.run([command, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Function to check if Tor is running
def is_tor_running():
    try:
        result = subprocess.run(["pgrep", "-x", "tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            print("Tor is not running.")
        return result.returncode == 0
    except Exception as e:
        print(f"Error checking if Tor is running: {e}")
        return False

# Function to monitor Tor process output
def monitor_tor_output(process, flag):
    try:
        for line in iter(process.stdout.readline, b''):
            decoded_line = line.decode()
            print(decoded_line.strip())
            if "Bootstrapped 100%" in decoded_line:
                flag[0] = True
                break
    except Exception as e:
        print(f"Error reading Tor process output: {e}")

# Function to start Tor using subprocess
def start_tor():
    if not is_command_installed("tor"):
        print("Tor is not installed. Please install Tor to proceed.")
        return None
    try:
        if is_tor_running():
            print("Tor is already running.")
            return None

        tor_process = subprocess.Popen(
            ["tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        bootstrapped_flag = [False]
        monitor_thread = Thread(target=monitor_tor_output, args=(tor_process, bootstrapped_flag))
        monitor_thread.start()

        for _ in range(30):  # Poll the tor process for up to 30 seconds
            if bootstrapped_flag[0]:
                return tor_process
            time.sleep(1)

        if not bootstrapped_flag[0]:
            raise Exception("Tor process failed to bootstrap.")
    except Exception as e:
        print(f"Error starting Tor: {e}")
        if 'tor_process' in locals() and tor_process:
            stderr_output = tor_process.stderr.read()
            print(f"Tor stderr: {stderr_output}")
        return None

# Function to configure the Tor proxy
def configure_tor_proxy():
    try:
        pass
    except Exception as e:
        print(f"Error configuring Tor proxy: {e}")
        sys.exit(1)

# Function to check the public IP via Tor
def check_ip_via_tor():
    try:
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        response = session.get("https://check.torproject.org/api/ip")
        data = response.json()
        return data["IsTor"]  # Returns True if using Tor, False if not
    except requests.exceptions.RequestException as e:
        print(f"Error checking the IP: {e}")
        return False

# Allowed commands and their validation patterns
allowed_commands = {
    "nmap": r"^nmap\s+-p\s+(80|443)\s+--script=http-vuln-.*\s+\S+$",
    "nikto": r"^nikto\s+-h\s+\S+$",
    "wpscan": r"^wpscan\s+--url\s+\S+$",
    "wapiti": r"^wapiti\s+-u\s+\S+$",
    "sqlmap": r"^sqlmap\s+--url\s+\S+\s+--(dbs|batch|forms)"
}

# Function to validate if a command matches the allowed patterns
def is_valid_command(command):
    for cmd, pattern in allowed_commands.items():
        if command.startswith(cmd) and re.match(pattern, command):
            return True
    return False

# Function to execute a command via Tor
def execute_command(command):
    if not command:
        print("Please enter a command.")
        return

    command = decrypt_data(command, key)  # Decrypt the command before executing it
    if command is None:
        return

    command_parts = shlex.split(command)

    if not command_parts:  # Validate if the list is empty before accessing its first element
        print("Error: No command provided.")
        return

    # Validate the command against allowed patterns
    if not is_valid_command(command):
        print("Error: Invalid command syntax.")
        return

    # Prepend 'torsocks' to force all traffic through Tor
    command_parts.insert(0, "torsocks")

    try:
        tor_process = start_tor()
        should_terminate = tor_process is not None

        if not tor_process and not is_tor_running():
            return

        configure_tor_proxy()

        if not check_ip_via_tor():
            print("Error: The connection is not using Tor.")
            user_input = input("Do you want to close the program? (yes/no): ").strip().lower()
            if user_input == 'yes':
                if tor_process:
                    tor_process.terminate()
                return
            else:
                print("Continuing without Tor...")

        if not is_command_installed(command_parts[1]):  # Check if the tool is installed
            print(f"{command_parts[1]} is not installed. Please install it to proceed.")
            if tor_process and should_terminate:
                tor_process.terminate()
            return

        # Execute the command securely
        process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        print(stdout)
        if stderr:
            print("ERROR: ", stderr)

        if process.returncode != 0:
            print(f"Command failed with return code {process.returncode}")

    except subprocess.SubprocessError as e:
        print(f"Error executing command: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        if tor_process and tor_process.poll() is None and should_terminate:
            tor_process.terminate()

# Function to handle SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print("\nCtrl+C detected. Terminating processes...")
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to list available commands
def list_commands():
    print("--list -- The List")
    print("--clear -- Clear The Terminal")
    print("--exit -- Exit")
    print("--allowed -- Only Allowed Commands")

# Function to clear the terminal screen
def clear():
    if os.name == "posix":  # Unix-like systems
        subprocess.run(["clear"])

# Function to display allowed commands
def allowed():
    print("ONLY VALID COMMANDS:")
    print("nmap -p 80 --script=http-vuln-* example.com")
    print("nmap -p 443 --script=http-vuln-* example.com")
    print("nikto -h http://example.com")
    print("wpscan --url http://example.com")
    print("wpscan --url http://example.com -e u,p")
    print("wapiti -u http://example.com")
    print("sqlmap --url http://example.com --dbs --batch --forms")

# Main function
def main():
    while True:
        print("Be_Anonymous")
        command = input("Enter the command you want to execute (Use --list to see the command face): ")

        if command.lower() == '--exit':
            break
        elif command.lower() == '--list':
            list_commands()
        elif command.lower() == '--clear':
            clear()
        elif command.lower() == '--allowed':
            allowed()
        else:
            # Encrypt the command before execution
            encrypted_command = encrypt_data(command, key)
            execute_command(encrypted_command)

# Start the application
if __name__ == "__main__":
    main()
