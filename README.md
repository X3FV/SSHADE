# SSHade - SSH Attack Framework

SSHade is an advanced SSH security testing and attack framework. It provides a suite of tools for brute force attacks, key-based authentication, persistence, and command execution, all with a stylish and user-friendly terminal interface.

## Features
- Advanced SSH brute force attacks (single, spray, threaded, smart, obfuscated)
- Credential scoring and prioritization for efficient attacks
- Adaptive error handling and recovery
- Colorful, stylish terminal output and progress bars
- Attack statistics and reporting
- SSH key persistence and cron job persistence
- Command execution and payload deployment

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd sshade
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requierements.txt
   ```

## Usage

Run the main tool with:
```bash
python3 sshade.py [OPTIONS]
```

### Main Arguments
| Option         | Description                                 |
| -------------- | ------------------------------------------- |
| `-t, --target` | Target IP address (required)                |
| `-p, --port`   | SSH port (default: 22)                      |
| `-m, --mode`   | Attack mode: `brute`, `key`, `persist`, `exec` (required) |
| `-u, --users`  | Username wordlist path                      |
| `-w, --passwords` | Password wordlist path                   |
| `-k, --key`    | SSH private key path                        |
| `-c, --command`| Command to execute on the target            |

### Attack Modes

#### 1. Brute Force Attack
Try all combinations of users and passwords.
```bash
python3 sshade.py -t <target_ip> -m brute [-u <userlist>] [-w <passlist>]
```
- Example:
  ```bash
  python3 sshade.py -t 192.168.1.100 -m brute -u data/wordlists/common_users.txt -w data/wordlists/common_pass.txt
  ```

#### 2. Key-based Authentication (Not yet implemented)
```bash
python3 sshade.py -t <target_ip> -m key -k <private_key_path>
```

#### 3. Persistence (SSH key or cron job)
Establish persistence on a compromised host.
```bash
python3 sshade.py -t <target_ip> -m persist -k <public_key_path>
```

#### 4. Command Execution
Run a command on the target after successful login.
```bash
python3 sshade.py -t <target_ip> -m exec -c "<command>"
```
- Example:
  ```bash
  python3 sshade.py -t 192.168.1.100 -m exec -c "whoami"
  ```

### Wordlists
- Default user and password wordlists are in `data/wordlists/`.
- You can specify your own with `-u` and `-w`.

### Output
- Colorful banners and progress bars
- Real-time status and statistics
- Success and error messages

## Example
```bash
python3 sshade.py -t 192.168.1.100 -m brute
```

## Configuration
- Edit `config.yaml` to customize timeouts, delays, wordlists, and more.

## Requirements
- Python 3.7+
- See `requierements.txt` for dependencies

## Disclaimer
This tool is for educational and authorized security testing only. Unauthorized use is prohibited.
