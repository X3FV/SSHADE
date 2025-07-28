import paramiko
import logging
import socket
import time
from typing import Optional, Tuple, Dict, Any
from pathlib import Path
from dataclasses import dataclass
from paramiko.ssh_exception import (
    SSHException,
    AuthenticationException,
    BadHostKeyException
)

# Configure logging
logging.getLogger("paramiko").setLevel(logging.WARNING)

@dataclass
class ConnectionResult:
    success: bool
    client: Optional[paramiko.SSHClient] = None
    error: Optional[str] = None
    banner: Optional[str] = None
    auth_method: Optional[str] = None

class SSHConnector:
    """Robust SSH connection handler with advanced features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._host_keys = paramiko.HostKeys()
        self._known_hosts = self._load_known_hosts()
        
    def _load_known_hosts(self) -> paramiko.HostKeys:
        """Load known hosts file if exists"""
        hosts_file = Path.home() / '.ssh' / 'known_hosts'
        if hosts_file.exists():
            try:
                self._host_keys.load(hosts_file)
                return self._host_keys
            except Exception as e:
                logging.debug(f"Failed to load known_hosts: {str(e)}")
        return paramiko.HostKeys()
    
    def _verify_host_key(self, hostname: str, key: paramiko.PKey) -> bool:
        """Verify host key against known_hosts"""
        if not self.config.get('verify_host_keys', True):
            return True
            
        known_key = self._known_hosts.lookup(hostname)
        if known_key and (key.get_name() in known_key):
            return known_key.compare(key)
        return False
    
    def _get_connection_params(self, host: str) -> Dict[str, Any]:
        """Prepare connection parameters from config"""
        return {
            'hostname': host,
            'port': self.config.get('port', 22),
            'timeout': self.config.get('timeout', 10),
            'banner_timeout': self.config.get('banner_timeout', 30),
            'auth_timeout': self.config.get('auth_timeout', 15),
            'allow_agent': self.config.get('allow_agent', False),
            'look_for_keys': self.config.get('look_for_keys', False)
        }
    
    def connect_with_password(
        self,
        host: str,
        username: str,
        password: str,
        **kwargs
    ) -> ConnectionResult:
        """Establish SSH connection using password authentication"""
        params = self._get_connection_params(host)
        params.update(kwargs)
        
        client = paramiko.SSHClient()
        policy = paramiko.AutoAddPolicy() if not self.config.get('verify_host_keys') else paramiko.RejectPolicy()
        client.set_missing_host_key_policy(policy)
        
        try:
            client.connect(username=username, password=password, **params)
            
            # Verify host key if enabled
            if self.config.get('verify_host_keys'):
                transport = client.get_transport()
                if transport:
                    key = transport.get_remote_server_key()
                    if not self._verify_host_key(host, key):
                        client.close()
                        return ConnectionResult(False, error="Host key verification failed")
            
            banner = client.get_transport().get_banner() if client.get_transport() else None
            return ConnectionResult(True, client=client, banner=banner, auth_method="password")
            
        except AuthenticationException:
            return ConnectionResult(False, error="Authentication failed")
        except BadHostKeyException:
            return ConnectionResult(False, error="Host key verification failed")
        except socket.timeout:
            return ConnectionResult(False, error="Connection timeout")
        except SSHException as e:
            return ConnectionResult(False, error=f"SSH error: {str(e)}")
        except Exception as e:
            return ConnectionResult(False, error=f"Connection error: {str(e)}")
    
    def connect_with_key(
        self,
        host: str,
        username: str,
        key_path: str,
        passphrase: Optional[str] = None,
        **kwargs
    ) -> ConnectionResult:
        """Establish SSH connection using key authentication"""
        params = self._get_connection_params(host)
        params.update(kwargs)
        
        client = paramiko.SSHClient()
        policy = paramiko.AutoAddPolicy() if not self.config.get('verify_host_keys') else paramiko.RejectPolicy()
        client.set_missing_host_key_policy(policy)
        
        try:
            key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
            client.connect(username=username, pkey=key, **params)
            
            # Verify host key if enabled
            if self.config.get('verify_host_keys'):
                transport = client.get_transport()
                if transport:
                    remote_key = transport.get_remote_server_key()
                    if not self._verify_host_key(host, remote_key):
                        client.close()
                        return ConnectionResult(False, error="Host key verification failed")
            
            banner = client.get_transport().get_banner() if client.get_transport() else None
            return ConnectionResult(True, client=client, banner=banner, auth_method="publickey")
            
        except paramiko.PasswordRequiredException:
            return ConnectionResult(False, error="Key requires passphrase")
        except paramiko.SSHException as e:
            return ConnectionResult(False, error=f"Key authentication failed: {str(e)}")
        except Exception as e:
            return ConnectionResult(False, error=f"Connection error: {str(e)}")
    
    def test_connection(
        self,
        host: str,
        port: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """Test if SSH port is open without full authentication"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout or self.config.get('timeout', 10))
        
        try:
            sock.connect((host, port or self.config.get('port', 22)))
            sock.close()
            return (True, None)
        except socket.timeout:
            return (False, "Connection timeout")
        except ConnectionRefusedError:
            return (False, "Connection refused")
        except Exception as e:
            return (False, str(e))
    
    def execute_command(
        self,
        client: paramiko.SSHClient,
        command: str,
        timeout: Optional[int] = None
    ) -> Tuple[bool, str, str]:
        """Execute command on established connection"""
        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=timeout or self.config.get('command_timeout', 30)
            )
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return (exit_status == 0, output, error)
        except SSHException as e:
            return (False, "", str(e))
    
    def interactive_shell(self, client: paramiko.SSHClient) -> None:
        """Start interactive shell session"""
        try:
            transport = client.get_transport()
            if transport:
                channel = transport.open_session()
                channel.get_pty()
                channel.invoke_shell()
                
                while True:
                    try:
                        # Handle user input and output
                        pass  # Implementation omitted for brevity
                    except KeyboardInterrupt:
                        break
        except Exception as e:
            logging.error(f"Shell error: {str(e)}")
    
    def check_auth_methods(self, host: str) -> Dict[str, bool]:
        """Check available authentication methods"""
        methods = {
            'password': False,
            'publickey': False,
            'gssapi-with-mic': False
        }
        
        try:
            transport = paramiko.Transport((host, self.config.get('port', 22)))
            transport.connect()
            methods.update(transport.auth_none(''))
            transport.close()
            return methods
        except Exception:
            return methods