import socket
import re
import json
import os
import sys
from typing import Dict, List, Optional

class SSHFingerprint:
    def __init__(self, host: str, port: int = 22, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.cve_db = self.load_cve_database()

    def load_cve_database(self) -> Dict:
        """Load the CVE database from JSON file"""
        try:
            cve_db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cve_db.json')
            with open(cve_db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load CVE database: {e}")
            return {}

    def grab_banner(self) -> str:
        """
        Connects to the SSH server and grabs the banner string.
        Returns the banner string if successful, or None if connection fails.
        """
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except (socket.timeout, socket.error, ConnectionRefusedError) as e:
            # Handle connection errors gracefully
            return None

    def parse_banner(self, banner: str) -> dict:
        """
        Parses the SSH banner string to extract SSH software, version, and possible OS.
        Returns a dictionary with keys: 'software', 'version', 'os' (os may be None if not found).
        """
        if not banner:
            return {'software': None, 'version': None, 'os': None}

        # Example banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
        # Regex to extract software and version
        software = None
        version = None
        os_info = None

        # Remove the SSH protocol prefix if present
        banner_clean = banner
        if banner.startswith("SSH-"):
            parts = banner.split('-', 2)
            if len(parts) == 3:
                banner_clean = parts[2]

        # Try to extract software and version
        # Common pattern: Software_Version OS_Info
        # e.g. OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
        match = re.match(r'([^\s_]+)_?([\d\.p]+)?\s*(.*)', banner_clean)
        if match:
            software = match.group(1)
            version = match.group(2)
            os_info = match.group(3).strip() if match.group(3) else None

        return {
            'software': software,
            'version': version,
            'os': os_info if os_info else None
        }

    def extract_version_number(self, version: str) -> str:
        """Extract the main version number from version string"""
        if not version:
            return None
        
        # Remove patch level indicators (p1, p2, etc.)
        version_clean = re.sub(r'p\d+', '', version)
        
        # Extract major.minor version
        match = re.match(r'(\d+\.\d+)', version_clean)
        if match:
            return match.group(1)
        
        return version_clean

    def check_vulnerabilities(self, software: str, version: str) -> List[Dict]:
        """Check for known vulnerabilities based on software and version"""
        vulnerabilities = []
        
        if not software or not version:
            return vulnerabilities
        
        # Extract main version number
        version_number = self.extract_version_number(version)
        if not version_number:
            return vulnerabilities
        
        # Check if software is in CVE database
        if software.lower() in self.cve_db:
            software_vulns = self.cve_db[software.lower()]
            
            # Check if version has vulnerabilities
            if version_number in software_vulns:
                for vuln in software_vulns[version_number]:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def run_vulnerability_scan(self, banner: str) -> Dict:
        """Run complete vulnerability scan including banner parsing and CVE checking"""
        # Parse banner
        parsed = self.parse_banner(banner)
        
        # Check for vulnerabilities
        vulnerabilities = self.check_vulnerabilities(parsed['software'], parsed['version'])
        
        return {
            'banner': banner,
            'parsed': parsed,
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities)
        }

    def prompt_for_exploit(self, vulnerability: Dict) -> bool:
        """Prompt user to run exploit if available"""
        if not vulnerability.get('exploit_available', False):
            return False
        
        print(f"\n⚠️  Vulnerability Detected: {vulnerability['cve_id']} — {vulnerability['title']}")
        print(f"📝 Description: {vulnerability['description']}")
        print(f"💥 Exploit module available. Run it now? [Y/n]: ", end="")
        
        try:
            response = input().strip().lower()
            return response in ['', 'y', 'yes']
        except KeyboardInterrupt:
            print("\n[!] Exploit execution cancelled by user.")
            return False

    def run_exploit(self, vulnerability: Dict, target: str, port: int) -> bool:
        """Run the exploit module for the detected vulnerability"""
        exploit_path = vulnerability.get('exploit_path')
        if not exploit_path:
            print("[!] No exploit path specified in vulnerability data.")
            return False
        
        # Construct full path to exploit
        project_root = os.path.dirname(os.path.dirname(__file__))
        full_exploit_path = os.path.join(project_root, exploit_path)
        
        if not os.path.exists(full_exploit_path):
            print(f"[!] Exploit module not found: {full_exploit_path}")
            return False
        
        print(f"[*] Running exploit module: {exploit_path}")
        
        try:
            # Import and run the exploit module
            sys.path.insert(0, os.path.dirname(full_exploit_path))
            
            # Import the exploit module
            module_name = os.path.splitext(os.path.basename(full_exploit_path))[0]
            exploit_module = __import__(module_name)
            
            # Find the main exploit class
            exploit_class = None
            for attr_name in dir(exploit_module):
                attr = getattr(exploit_module, attr_name)
                if hasattr(attr, '__name__') and 'Exploit' in attr.__name__:
                    exploit_class = attr
                    break
            
            if exploit_class:
                # Create exploit instance and run it
                exploit_instance = exploit_class(target, port)
                exploit_instance.run()
                return True
            else:
                print("[!] Could not find exploit class in module.")
                return False
                
        except Exception as e:
            print(f"[!] Error running exploit: {e}")
            return False

    def fingerprint_with_vulnerabilities(self) -> Dict:
        """Complete fingerprinting with vulnerability detection"""
        print(f"[*] Fingerprinting SSH service on {self.host}:{self.port}")
        
        # Grab banner
        banner = self.grab_banner()
        if not banner:
            print(f"[!] Could not connect to {self.host}:{self.port}")
            return {
                'banner': None,
                'parsed': {'software': None, 'version': None, 'os': None},
                'vulnerabilities': [],
                'vulnerability_count': 0
            }
        
        print(f"[+] SSH Banner: {banner}")
        
        # Run vulnerability scan
        scan_results = self.run_vulnerability_scan(banner)
        
        # Display parsed information
        parsed = scan_results['parsed']
        print(f"[+] Software: {parsed['software']}")
        print(f"[+] Version: {parsed['version']}")
        if parsed['os']:
            print(f"[+] OS Info: {parsed['os']}")
        
        # Display vulnerabilities
        vulnerabilities = scan_results['vulnerabilities']
        if vulnerabilities:
            print(f"\n[!] Found {len(vulnerabilities)} vulnerability(ies):")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['cve_id']} — {vuln['title']}")
                print(f"   Severity: {vuln['severity']}")
                print(f"   Description: {vuln['description']}")
                
                if vuln.get('exploit_available', False):
                    print(f"   💥 Exploit Available: {vuln['exploit_path']}")
                    
                    # Prompt for exploit execution
                    if self.prompt_for_exploit(vuln):
                        self.run_exploit(vuln, self.host, self.port)
        else:
            print(f"\n[+] No known CVEs matched for this SSH version.")
        
        return scan_results
