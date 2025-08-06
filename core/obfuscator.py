import random
import string
import base64
import zlib
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re

class Obfuscator:
    """Advanced command and traffic obfuscation engine"""
    
    def __init__(self, config: dict):
        self.config = config.get('obfuscation', {})
        self.encryption_key = self._derive_key(
            self.config.get('encryption_key', 'default-key')
        )
        self.obfuscation_level = self.config.get('level', 2)  # 1-3
        
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        salt = b'sshade_obfuscator_'  # Should be configurable in production
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _random_case(self, s: str) -> str:
        """Randomize character casing"""
        return ''.join(
            c.upper() if random.choice([True, False]) else c.lower()
            for c in s
        )
    
    def _insert_junk(self, s: str) -> str:
        """Insert random junk characters"""
        junk_chars = [' ', '\t', '#', ';', '&']
        result = []
        for c in s:
            if random.random() < 0.3:  # 30% chance to insert junk
                result.append(random.choice(junk_chars))
            result.append(c)
        return ''.join(result)
    
    def _encode_basic(self, cmd: str) -> str:
        """Basic obfuscation using base64"""
        encoded = base64.b64encode(cmd.encode()).decode()
        return f"echo {encoded} | base64 -d | sh"
    
    def _encode_advanced(self, cmd: str) -> str:
        """Advanced multi-layer obfuscation"""
        # First layer: compression + base64
        compressed = zlib.compress(cmd.encode())
        b64_encoded = base64.b64encode(compressed).decode()
        
        # Second layer: encryption
        fernet = Fernet(self.encryption_key)
        encrypted = fernet.encrypt(b64_encoded.encode()).decode()
        
        # Third layer: random formatting
        parts = [
            '$(echo {enc} | base64 -d | fernet-decrypt)'.format(enc=encrypted),
            '| zlib-decompress',
            '| sh'
        ]
        random.shuffle(parts)
        return ' '.join(parts)
    
    def _encode_expert(self, cmd: str) -> str:
        """Expert-level obfuscation with multiple techniques"""
        # Generate random variable names
        var1 = ''.join(random.choices(string.ascii_lowercase, k=6))
        var2 = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        # Build multi-stage decoding command
        template = f"""
        {var1}=$(mktemp);
        {var2}=$(mktemp);
        echo {base64.b64encode(cmd.encode()).decode()} | base64 -d > ${var1};
        cat ${var1} | {self._insert_junk('sh')} > ${var2};
        rm ${var1} ${var2}
        """
        
        # Clean up and randomize
        template = re.sub(r'\s+', ' ', template).strip()
        return self._random_case(template)
    
    def obfuscate_command(self, cmd: str) -> str:
        """Obfuscate a command based on configured level"""
        if not cmd or not isinstance(cmd, str):
            return cmd
            
        if self.obfuscation_level == 1:
            return self._random_case(self._insert_junk(cmd))
        elif self.obfuscation_level == 2:
            return self._encode_basic(cmd)
        elif self.obfuscation_level >= 3:
            return self._encode_advanced(cmd)
        return cmd
    
    def deobfuscate(self, obfuscated: str) -> Optional[str]:
        """Attempt to deobfuscate a command (for analysis)"""
        try:
            # Check for base64 pattern
            b64_match = re.search(r'echo\s+([A-Za-z0-9+/=]+)\s+\|\s*base64', obfuscated)
            if b64_match:
                return base64.b64decode(b64_match.group(1)).decode()
                
            # Check for encrypted pattern
            enc_match = re.search(r'fernet-decrypt\)\s*\|\s*zlib-decompress', obfuscated)
            if enc_match:
                fernet = Fernet(self.encryption_key)
                encrypted = re.search(r'echo\s+([^\|]+)', obfuscated).group(1)
                decrypted = fernet.decrypt(encrypted.encode())
                return zlib.decompress(base64.b64decode(decrypted)).decode()
                
        except Exception:
            return None
        return obfuscated
    
    def generate_alias(self) -> str:
        """Generate obfuscated alias for common commands"""
        aliases = {
            'ls': 'list_files',
            'cat': 'show_content',
            'ssh': 'secure_shell',
            'id': 'user_info'
        }
        base_alias = random.choice(list(aliases.keys()))
        return f"alias {self._random_case(aliases[base_alias])}='{self.obfuscate_command(base_alias)}'"
    
    def obfuscate_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Obfuscate an entire file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            obfuscated = self.obfuscate_command(content)
            
            new_path = f"{file_path}.obf"
            with open(new_path, 'w') as f:
                f.write("#!/bin/sh\n")
                f.write(obfuscated)
            
            return (True, new_path)
        except Exception as e:
            return (False, str(e))