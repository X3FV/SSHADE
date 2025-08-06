#!/usr/bin/env python3
"""
SSHade Setup Script
Interactive configuration for API keys and attack server settings
"""

import os
import sys
import yaml
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class SSHadeSetup:
    def __init__(self):
        self.config_file = "config.yaml"
        self.env_file = ".env"
        self.config = {}
        
    def print_banner(self):
        """Display setup banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Fore.RED}                    SSHade Setup Wizard                    {Fore.CYAN}║
║{Fore.YELLOW}              Configure API Keys & Settings                {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def print_status(self, message: str, status_type: str = "info"):
        """Print colored status messages"""
        icons = {
            "info": "ℹ️",
            "success": "✔️",
            "warning": "⚠️",
            "error": "✖️"
        }
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        icon = icons.get(status_type, "")
        color = colors.get(status_type, Fore.WHITE)
        print(f"{color}{icon} {message}{Style.RESET_ALL}")

    def load_config(self):
        """Load existing configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f)
                self.print_status("Loaded existing configuration", "success")
            else:
                self.print_status("No existing configuration found", "warning")
        except Exception as e:
            self.print_status(f"Error loading config: {e}", "error")

    def setup_api_keys(self):
        """Interactive API key setup"""
        print(f"\n{Fore.CYAN}🔑 API Keys Configuration{Style.RESET_ALL}")
        print("Enter your API keys (press Enter to skip):\n")
        
        api_keys = {}
        
        # Shodan API Key
        print(f"{Fore.YELLOW}Shodan API Key{Style.RESET_ALL}")
        print("Get your key from: https://account.shodan.io/register")
        shodan_key = input("Shodan API Key: ").strip()
        if shodan_key:
            api_keys['SHODAN_API_KEY'] = shodan_key
            self.print_status("Shodan API key configured", "success")
        
        # VirusTotal API Key
        print(f"\n{Fore.YELLOW}VirusTotal API Key{Style.RESET_ALL}")
        print("Get your key from: https://www.virustotal.com/gui/join-us")
        vt_key = input("VirusTotal API Key: ").strip()
        if vt_key:
            api_keys['VIRUSTOTAL_API_KEY'] = vt_key
            self.print_status("VirusTotal API key configured", "success")
        
        # Censys API Key
        print(f"\n{Fore.YELLOW}Censys API Key{Style.RESET_ALL}")
        print("Get your key from: https://censys.io/register")
        censys_key = input("Censys API Key: ").strip()
        if censys_key:
            api_keys['CENSYS_API_KEY'] = censys_key
            self.print_status("Censys API key configured", "success")
        
        # Censys Secret
        if censys_key:
            censys_secret = input("Censys Secret: ").strip()
            if censys_secret:
                api_keys['CENSYS_SECRET'] = censys_secret
                self.print_status("Censys secret configured", "success")
        
        return api_keys

    def setup_attack_server(self):
        """Interactive attack server setup"""
        print(f"\n{Fore.CYAN}🎯 Attack Server Configuration{Style.RESET_ALL}")
        print("Configure your attack server settings:\n")
        
        server_config = {}
        
        # Server Host
        print(f"{Fore.YELLOW}Attack Server Host{Style.RESET_ALL}")
        server_host = input("Server Host (e.g., 192.168.1.100): ").strip()
        if server_host:
            server_config['ATTACK_SERVER_HOST'] = server_host
            self.print_status("Attack server host configured", "success")
        
        # Server Port
        print(f"\n{Fore.YELLOW}Attack Server Port{Style.RESET_ALL}")
        server_port = input("Server Port (default: 22): ").strip()
        if server_port:
            server_config['ATTACK_SERVER_PORT'] = server_port
            self.print_status("Attack server port configured", "success")
        
        # Default Username
        print(f"\n{Fore.YELLOW}Default Username{Style.RESET_ALL}")
        default_user = input("Default Username (e.g., admin): ").strip()
        if default_user:
            server_config['DEFAULT_USERNAME'] = default_user
            self.print_status("Default username configured", "success")
        
        # Default Password
        print(f"\n{Fore.YELLOW}Default Password{Style.RESET_ALL}")
        default_pass = input("Default Password: ").strip()
        if default_pass:
            server_config['DEFAULT_PASSWORD'] = default_pass
            self.print_status("Default password configured", "success")
        
        return server_config

    def setup_proxy(self):
        """Interactive proxy setup"""
        print(f"\n{Fore.CYAN}🌐 Proxy Configuration{Style.RESET_ALL}")
        print("Configure proxy settings (press Enter to skip):\n")
        
        proxy_config = {}
        
        # HTTP Proxy
        print(f"{Fore.YELLOW}HTTP Proxy{Style.RESET_ALL}")
        http_proxy = input("HTTP Proxy (e.g., http://proxy:8080): ").strip()
        if http_proxy:
            proxy_config['HTTP_PROXY'] = http_proxy
            self.print_status("HTTP proxy configured", "success")
        
        # HTTPS Proxy
        print(f"\n{Fore.YELLOW}HTTPS Proxy{Style.RESET_ALL}")
        https_proxy = input("HTTPS Proxy (e.g., https://proxy:8080): ").strip()
        if https_proxy:
            proxy_config['HTTPS_PROXY'] = https_proxy
            self.print_status("HTTPS proxy configured", "success")
        
        # SOCKS5 Proxy
        print(f"\n{Fore.YELLOW}SOCKS5 Proxy{Style.RESET_ALL}")
        socks5_proxy = input("SOCKS5 Proxy (e.g., socks5://proxy:1080): ").strip()
        if socks5_proxy:
            proxy_config['SOCKS5_PROXY'] = socks5_proxy
            self.print_status("SOCKS5 proxy configured", "success")
        
        return proxy_config

    def setup_ssh_keys(self):
        """Interactive SSH key setup"""
        print(f"\n{Fore.CYAN}🔐 SSH Keys Configuration{Style.RESET_ALL}")
        print("Configure SSH key paths (press Enter to use defaults):\n")
        
        ssh_config = {}
        
        # Private Key Path
        print(f"{Fore.YELLOW}SSH Private Key Path{Style.RESET_ALL}")
        print("Default: keys/demo_id_rsa")
        private_key = input("Private Key Path: ").strip()
        if private_key:
            ssh_config['SSH_PRIVATE_KEY_PATH'] = private_key
            self.print_status("SSH private key path configured", "success")
        
        # Public Key Path
        print(f"\n{Fore.YELLOW}SSH Public Key Path{Style.RESET_ALL}")
        print("Default: keys/demo_id_rsa.pub")
        public_key = input("Public Key Path: ").strip()
        if public_key:
            ssh_config['SSH_PUBLIC_KEY_PATH'] = public_key
            self.print_status("SSH public key path configured", "success")
        
        return ssh_config

    def write_env_file(self, config_dict):
        """Write configuration to .env file"""
        try:
            with open(self.env_file, 'w') as f:
                f.write("# SSHade Environment Configuration\n")
                f.write("# Generated by setup.py\n\n")
                
                for key, value in config_dict.items():
                    f.write(f"{key}={value}\n")
            
            self.print_status(f"Configuration saved to {self.env_file}", "success")
            return True
        except Exception as e:
            self.print_status(f"Error writing .env file: {e}", "error")
            return False

    def show_usage_examples(self):
        """Show usage examples with configured settings"""
        print(f"\n{Fore.CYAN}📖 Usage Examples{Style.RESET_ALL}")
        print("Here are some examples using your configured settings:\n")
        
        print(f"{Fore.GREEN}Basic brute force attack:{Style.RESET_ALL}")
        print("python3 sshade.py -t <target> -m brute\n")
        
        print(f"{Fore.GREEN}With custom credentials:{Style.RESET_ALL}")
        print("python3 sshade.py -t <target> -m brute -u users.txt -w passwords.txt\n")
        
        print(f"{Fore.GREEN}SSH key persistence:{Style.RESET_ALL}")
        print("python3 sshade.py -t <target> -m persist -k keys/demo_id_rsa.pub\n")
        
        print(f"{Fore.GREEN}Command execution:{Style.RESET_ALL}")
        print("python3 sshade.py -t <target> -m exec -c 'whoami'\n")
        
        print(f"{Fore.GREEN}Network discovery:{Style.RESET_ALL}")
        print("python3 sshade.py -t 192.168.1.0/24 -m discover\n")
        
        print(f"{Fore.GREEN}Vulnerability fingerprinting:{Style.RESET_ALL}")
        print("python3 sshade.py -t <target> --fingerprint\n")

    def run(self):
        """Run the setup wizard"""
        self.print_banner()
        
        # Load existing config
        self.load_config()
        
        # Collect all configuration
        all_config = {}
        
        # Setup API keys
        api_keys = self.setup_api_keys()
        all_config.update(api_keys)
        
        # Setup attack server
        server_config = self.setup_attack_server()
        all_config.update(server_config)
        
        # Setup proxy
        proxy_config = self.setup_proxy()
        all_config.update(proxy_config)
        
        # Setup SSH keys
        ssh_config = self.setup_ssh_keys()
        all_config.update(ssh_config)
        
        # Write configuration
        if all_config:
            if self.write_env_file(all_config):
                self.print_status("Setup completed successfully!", "success")
                self.show_usage_examples()
            else:
                self.print_status("Setup failed!", "error")
        else:
            self.print_status("No configuration provided. Using defaults.", "warning")
            self.show_usage_examples()

def main():
    """Main function"""
    try:
        setup = SSHadeSetup()
        setup.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Setup cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Setup failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 