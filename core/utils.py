import os
import sys
import time
import random
import string
import logging
import hashlib
import platform
import subprocess
from typing import Optional, List, Dict, Tuple, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum, auto

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.NullHandler()]
)
logger = logging.getLogger('sshade_utils')

class OSType(Enum):
    LINUX = auto()
    WINDOWS = auto()
    MACOS = auto()
    UNKNOWN = auto()

@dataclass
class CommandResult:
    success: bool
    output: str
    error: str
    exit_code: int
    execution_time: float

class Utils:
    """Core utilities for SSHade framework"""
    
    @staticmethod
    def get_os() -> OSType:
        """Detect the operating system type"""
        system = platform.system().lower()
        if 'linux' in system:
            return OSType.LINUX
        elif 'windows' in system:
            return OSType.WINDOWS
        elif 'darwin' in system:
            return OSType.MACOS
        return OSType.UNKNOWN
    
    @staticmethod
    def random_string(length: int = 8) -> str:
        """Generate a random alphanumeric string"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def calculate_checksum(file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file checksum using specified algorithm"""
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)
        with open(file_path, 'rb') as f:
            return hash_func(f.read()).hexdigest()
    
    @staticmethod
    def is_root() -> bool:
        """Check if running with root privileges"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Windows systems
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    @staticmethod
    def execute_local(
        command: str,
        timeout: int = 30,
        shell: bool = False
    ) -> CommandResult:
        """Execute a local command with timeout"""
        start_time = time.time()
        try:
            process = subprocess.Popen(
                command if shell else command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=shell
            )
            stdout, stderr = process.communicate(timeout=timeout)
            return CommandResult(
                success=process.returncode == 0,
                output=stdout.decode().strip(),
                error=stderr.decode().strip(),
                exit_code=process.returncode,
                execution_time=time.time() - start_time
            )
        except subprocess.TimeoutExpired:
            process.kill()
            return CommandResult(
                False,
                "",
                "Command timed out",
                -1,
                time.time() - start_time
            )
        except Exception as e:
            return CommandResult(
                False,
                "",
                str(e),
                -1,
                time.time() - start_time
            )
    
    @staticmethod
    def file_exists(file_path: str) -> bool:
        """Check if file exists and is accessible"""
        try:
            return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
        except Exception:
            return False
    
    @staticmethod
    def create_temp_file(
        content: str = "",
        prefix: str = "sshade_",
        suffix: str = ".tmp"
    ) -> Optional[str]:
        """Create a temporary file with optional content"""
        try:
            temp_dir = os.path.join(os.path.sep, 'tmp') if Utils.get_os() == OSType.LINUX else os.environ.get('TEMP', '')
            if not temp_dir:
                temp_dir = os.path.dirname(os.path.abspath(__file__))
                
            temp_path = os.path.join(temp_dir, prefix + Utils.random_string(6) + suffix)
            with open(temp_path, 'w') as f:
                if content:
                    f.write(content)
            return temp_path
        except Exception as e:
            logger.error(f"Failed to create temp file: {str(e)}")
            return None
    
    @staticmethod
    def clean_temp_files(prefix: str = "sshade_") -> int:
        """Clean up temporary files created by the framework"""
        count = 0
        temp_dir = os.path.join(os.path.sep, 'tmp') if Utils.get_os() == OSType.LINUX else os.environ.get('TEMP', '')
        if not temp_dir:
            return 0
            
        try:
            for filename in os.listdir(temp_dir):
                if filename.startswith(prefix):
                    os.remove(os.path.join(temp_dir, filename))
                    count += 1
        except Exception:
            pass
        return count
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate an IP address (v4 or v6)"""
        import socket
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    @staticmethod
    def port_in_use(port: int, host: str = '127.0.0.1') -> bool:
        """Check if a port is in use"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((host, port)) == 0
    
    @staticmethod
    def human_readable_size(size: int, decimal_places: int = 2) -> str:
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                break
            size /= 1024.0
        return f"{size:.{decimal_places}f} {unit}"
    
    @staticmethod
    def parse_ssh_key(key_path: str) -> Optional[Dict[str, Any]]:
        """Parse SSH key file and return metadata"""
        try:
            from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key
            
            key_classes = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]
            for key_class in key_classes:
                try:
                    key = key_class.from_private_key_file(key_path)
                    return {
                        'type': key_class.__name__.replace('Key', ''),
                        'bits': key.get_bits() if hasattr(key, 'get_bits') else None,
                        'fingerprint': key.get_fingerprint().hex(),
                        'comment': getattr(key, 'comment', '')
                    }
                except Exception:
                    continue
            return None
        except ImportError:
            return None
    
    @staticmethod
    def get_network_info() -> Dict[str, Any]:
        """Get basic network information"""
        import socket
        import netifaces
        
        info = {
            'hostname': socket.gethostname(),
            'interfaces': {}
        }
        
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                info['interfaces'][interface] = {
                    'ipv4': addrs.get(netifaces.AF_INET, []),
                    'ipv6': addrs.get(netifaces.AF_INET6, []),
                    'mac': addrs.get(netifaces.AF_LINK, [])
                }
        except Exception:
            pass
            
        return info
    
    @staticmethod
    def is_proxy_active() -> bool:
        """Check if system proxy is active"""
        proxy_vars = ['http_proxy', 'https_proxy', 'all_proxy']
        return any(os.environ.get(var) for var in proxy_vars)
    
    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
        """Get information about a running process"""
        try:
            import psutil
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'cmdline': proc.cmdline(),
                'create_time': proc.create_time(),
                'username': proc.username()
            }
        except (ImportError, psutil.NoSuchProcess):
            return None