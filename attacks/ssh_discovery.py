import socket
import ipaddress
from typing import List, Tuple
from colorama import Fore, Style

class SSHDiscovery:
    def __init__(self, port: int = 22, timeout: float = 1.0):
        self.port = port
        self.timeout = timeout

    def scan_host(self, ip: str) -> bool:
        """Check if SSH port is open on the given IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_network(self, network: str) -> List[str]:
        """Scan the given network (CIDR notation) for hosts with open SSH port"""
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print(f"{Fore.RED}Invalid network address: {network}{Style.RESET_ALL}")
            return []

        print(f"{Fore.CYAN}Scanning network {network} for SSH hosts on port {self.port}...{Style.RESET_ALL}")
        live_hosts = []
        total_hosts = net.num_addresses
        for count, ip in enumerate(net.hosts(), 1):
            ip_str = str(ip)
            print(f"\rScanning {ip_str} ({count}/{total_hosts})", end="")
            if self.scan_host(ip_str):
                print(f"\n{Fore.GREEN}Found SSH host: {ip_str}{Style.RESET_ALL}")
                live_hosts.append(ip_str)
        print()
        print(f"{Fore.YELLOW}Scan complete. {len(live_hosts)} SSH hosts found.{Style.RESET_ALL}")
        return live_hosts
