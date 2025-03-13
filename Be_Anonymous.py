import os
import sys
import platform
import subprocess
import socks
import socket
import requests
import time
import json
import shlex
from cryptography.fernet import Fernet

# Verified if windows if windows close windows
if platform.system() == "Windows":
    print("Este script solo funciona en sistemas operativos Linux.")
    sys.exit()

# Generate a key for encryption and decryption
def generate_key():
    return Fernet.generate_key()

# Save the key to a file
def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

# Load the key from a file
def load_key(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Function to decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Load or generate encryption key
key_file = "secret.key"
if not os.path.exists(key_file):
    key = generate_key()
    save_key(key, key_file)
    os.chmod(key_file, 0o600)  # Set file permissions to read/write for the owner only
else:
    try:
        key = load_key(key_file)
    except Exception as e:
        print(f"Error loading the key: {e}")
        sys.exit(1)

# Function to check if a command is installed
def is_command_installed(command):
    try:
        subprocess.run([command, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Function to start Tor using subprocess
def start_tor():
    if not is_command_installed("tor"):
        print("Tor is not installed. Please install Tor to proceed.")
        return None
    try:
        tor_process = subprocess.Popen(["tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(10):  # Poll the tor process for up to 10 seconds
            if tor_process.poll() is None:
                time.sleep(1)
            else:
                raise Exception("Tor process failed to start.")
        return tor_process
    except Exception as e:
        print(f"Error starting Tor: {e}")
        return None

# Function to configure the Tor proxy
def configure_tor_proxy():
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket

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
    except Exception as e:
        print(f"Error checking the IP: {e}")
        return False

# Function to execute a command via Tor (only for nmap, nikto, wpscan, and wapiti)
def execute_command(command):
    if not command:
        print("Please enter a command.")
        return

    allowed_commands = ['nmap', 'nikto', 'wpscan', 'wapiti']
    command_parts = shlex.split(command)

    if command_parts[0].lower() not in allowed_commands:
        print(f"Error: Only the following commands are allowed: {', '.join(allowed_commands)}.")
        return

    if command_parts[0].lower() == "nmap":
        if not any(script in command for script in ['http-vuln-', '-p 80', '-p 443', '--script=http-vuln-*']):
            print("Error: Only vulnerability scans or web-related port scans are allowed with nmap.")
            return

    if command_parts[0].lower() == "wpscan":
        if '--url' not in command_parts:
            print("Error: Only vulnerability scans allowed with wpscan --url")
            return

    if command_parts[0].lower() == "wapiti":
        if '-u' not in command_parts:
            print("Error: Only vulnerability scans allowed with wapiti -u")
            return

    if command_parts[0].lower() == "nikto":
        if "-h" not in command_parts:
            print("Error: Nikto must be used with the -h option to specify a website.")
            return

    try:
        tor_process = start_tor()
        if not tor_process:
            return

        configure_tor_proxy()

        if not check_ip_via_tor():
            print("Error: The connection is not using Tor.")
            user_input = input("Do you want to close the program? (yes/no): ").strip().lower()
            if user_input == 'yes':
                tor_process.terminate()
                return
            else:
                print("Continuing without Tor...")

        if not is_command_installed(command_parts[0]):
            print(f"{command_parts[0]} is not installed. Please install it to proceed.")
            tor_process.terminate()
            return

        process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            output = process.stdout.readline()
            if process.poll() is not None and output == '':
                break
            if output:
                print(output.strip())

        process.terminate()

    except Exception as e:
        print(f"An error occurred while executing the command: {e}")
    finally:
        if tor_process:
            tor_process.terminate()

def list_commands():
    print("--list -- The List")
    print("--clear -- Clear The Terminal")
    print("--exit -- Exit")
    print("--allowed -- Only Allowed Commands")

def clear():
    if platform.system() == "Unix":
        subprocess.run(["clear"])
    else:
        subprocess.run(["cls"])

def allowed():
    print("ONLY VALID COMMANDS:")
    print("nmap -p 80 --script=http-vuln-* example.com")
    print("nmap -p 443 --script=http-vuln-* example.com")
    print("nikto -h http://example.com")
    print("wpscan --url http://example.com")
    print("wapiti -u http://example.com")

# Main function
def main():
    while True:
        print("PROTOCOL DUCK")
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
            execute_command(command)

# Start the application
if __name__ == "__main__":
    main()
