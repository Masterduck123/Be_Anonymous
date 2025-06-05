# ANOM

## Description

**Anom** is a command-line tool designed for privacy and anonymity. It allows you to securely execute terminal commands through the Tor network, ensuring that your network traffic is anonymized. All commands are encrypted before execution, and the tool verifies both the health of your Tor connection and the presence of necessary dependencies. For your safety, it blocks potentially dangerous command patterns.

> **Note**: Anom is intended for Linux systems only. It will not run on Windows.

## Main Features

- Executes commands through the Tor network using `torsocks`, keeping your IP address private.
- Encrypts commands before execution for an extra layer of security.
- Automatically checks if Tor is running and healthy; can start or restart Tor as needed.
- Verifies the installation of required dependencies (`tor`, `torsocks`, and the desired command).
- Blocks forbidden or dangerous command patterns (such as pipes, command chaining, or destructive commands).
- Simple command-line interface with built-in help and command listing.
- Handles encryption keys securely and regenerates them if missing or invalid.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Masterduck123/Anom.git
   cd Anom
   ```

2. **Install dependencies:**
   - Python 3.8 or higher.
   - [Tor](https://www.torproject.org/download/)
   - [torsocks](https://manpages.debian.org/unstable/torsocks/torsocks.1.en.html)
   - Python packages:
     ```bash
     pip install cryptography requests
     ```

3. **(Optional) Install any additional command-line tools you intend to use via Anom.**

## Usage

```bash
python3 anom.py
```

- Use `--list` to list built-in commands.
- Use `--help` for user instructions.
- Enter your desired command to execute it anonymously through Tor.
- Use `--clear` to clear the terminal.
- Use `--exit` to quit.

**Example session:**
```
Enter the command you want to execute (Use --list to see the command face): curl ifconfig.me
```

## Requirements

- Linux-based system (not Windows)
- Python 3.8+
- Tor and torsocks installed and running
- Network access for Tor

## Contribution

Contributions are welcome! Please open an issue or a pull request to suggest changes or improvements.

## Authors

- [Masterduck123](https://github.com/Masterduck123)

## License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).
