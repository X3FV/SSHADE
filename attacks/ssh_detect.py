import time
import paramiko
from typing import Optional, Dict

class SSHHoneypotDetector:
    """Detect common SSH honeypots by analyzing banner, login response time, and file structure"""

    known_honeypot_banners = {
        "kippo": ["kippo", "ssh honeypot", "fake ssh"],
        "cowrie": ["cowrie", "ssh honeypot", "fake ssh"],
        "honeyssh": ["honeyssh", "ssh honeypot", "fake ssh"],
    }

    honeypot_file_paths = [
        "/etc/kippo",
        "/etc/cowrie",
        "/etc/honeyssh",
        "/var/log/kippo",
        "/var/log/cowrie",
        "/var/log/honeyssh",
        "/usr/share/kippo",
        "/usr/share/cowrie",
        "/usr/share/honeyssh",
        "/home/kippo",
        "/home/cowrie",
        "/home/honeyssh",
    ]

    def __init__(self, port: int = 22, timeout: int = 10):
        self.port = port
        self.timeout = timeout

    def detect_banner_anomalies(self, banner: Optional[str]) -> Optional[str]:
        """Check if banner matches known honeypot banners"""
        if not banner:
            return None
        banner_lower = banner.lower()
        for honeypot, keywords in self.known_honeypot_banners.items():
            if any(keyword in banner_lower for keyword in keywords):
                return honeypot
        return None

    def measure_login_response_time(self, host: str) -> Optional[float]:
        """Measure time to establish SSH connection (login prompt)"""
        start_time = time.time()
        try:
            client = paramiko.Transport((host, self.port))
            client.banner_timeout = self.timeout
            client.start_client(timeout=self.timeout)
            end_time = time.time()
            client.close()
            return end_time - start_time
        except Exception:
            return None

    def detect_honeypot_file_structure(self, ssh_client: paramiko.SSHClient) -> bool:
        """Check for presence of files/directories typical of honeypots"""
        sftp = None
        try:
            sftp = ssh_client.open_sftp()
            for path in self.honeypot_file_paths:
                try:
                    sftp.stat(path)
                    return True  # Found honeypot file or directory
                except IOError:
                    continue
            return False
        except Exception:
            return False
        finally:
            if sftp:
                sftp.close()

    def detect(self, host: str) -> Dict:
        """Run all detection checks and return results"""
        results = {
            "banner": None,
            "banner_honeypot": None,
            "login_response_time": None,
            "login_response_suspicious": False,
            "honeypot_file_structure": False,
            "honeypot_detected": False,
            "honeypot_name": None,
        }

        # Get banner
        try:
            transport = paramiko.Transport((host, self.port))
            transport.banner_timeout = self.timeout
            transport.start_client(timeout=self.timeout)
            banner = transport.get_banner()
            banner_str = banner.decode() if banner else None
            results["banner"] = banner_str
            results["banner_honeypot"] = self.detect_banner_anomalies(banner_str)
            transport.close()
        except Exception:
            results["banner"] = None
            results["banner_honeypot"] = None

        # Measure login response time
        response_time = self.measure_login_response_time(host)
        results["login_response_time"] = response_time
        # Heuristic: suspicious if response time < 0.5s or > 10s (tunable)
        if response_time is not None and (response_time < 0.5 or response_time > 10):
            results["login_response_suspicious"] = True

        # Check file structure if possible
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Attempt anonymous or default connection to check files
            ssh_client.connect(host, port=self.port, username="root", password="", timeout=self.timeout, banner_timeout=self.timeout)
            results["honeypot_file_structure"] = self.detect_honeypot_file_structure(ssh_client)
        except Exception:
            results["honeypot_file_structure"] = False
        finally:
            ssh_client.close()

        # Determine if honeypot detected by any method
        if results["banner_honeypot"] or results["login_response_suspicious"] or results["honeypot_file_structure"]:
            results["honeypot_detected"] = True
            results["honeypot_name"] = results["banner_honeypot"] or "unknown"

        return results
