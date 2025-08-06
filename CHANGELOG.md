# Changelog

All notable changes to SSHade will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Environment variable support for sensitive configuration
- Demo SSH keys for safe testing
- Comprehensive security documentation
- MIT License for public release
- Security policy and responsible disclosure guidelines
- Contributing guidelines
- Proper .gitignore for sensitive files

### Changed
- Updated configuration to use environment variables
- Replaced real SSH keys with demo keys
- Enhanced README with security disclaimers
- Fixed requirements.txt filename typo

### Security
- Removed all real SSH keys and credentials
- Added environment variable support for API keys
- Implemented proper security warnings
- Added responsible disclosure policy

## [1.0.0] - 2024-01-XX

### Added
- Advanced SSH brute force attacks with throttling
- Credential scoring and prioritization
- Adaptive error handling and recovery
- Colorful terminal interface with progress tracking
- SSH key persistence and cron job persistence
- Command execution and payload deployment
- Credential harvesting (wrapper and keylogger)
- Network discovery of SSH hosts
- Honeypot detection and analysis
- SSH banner fingerprinting with vulnerability detection
- Rootkit deployment for stealth and persistence
- SSH worm propagation capabilities
- Self-destruct mechanism for cleanup
- Time-based execution windows
- Interactive shell after successful login
- CVE database integration with exploit modules

### Security Features
- Self-destruct mechanism for secure cleanup
- Time-based execution windows for stealth operations
- Background monitoring for tamper detection
- Secure file deletion using shred and overwriting
- Log clearing capabilities
- Fake reboot simulation

### Supported Vulnerabilities
- CVE-2018-15473: User Enumeration via Authentication Response Timing
- CVE-2016-6210: User Enumeration via Timing Attack

### Exploit Modules
- CVE-2018-15473/exploit.py: Complete user enumeration exploit
- CVE-2016-6210/exploit.py: User enumeration via timing attack
- vulnerability_scanner.py: Standalone vulnerability scanner

## [0.9.0] - 2024-01-XX

### Added
- Initial development version
- Basic SSH attack framework
- Core functionality implementation
- Basic documentation

### Security
- Initial security review
- Basic security features implementation

---

## Version History

- **1.0.0**: First public release with comprehensive security features
- **0.9.0**: Initial development version

## Security Advisories

No security advisories have been issued yet.

## Breaking Changes

- **1.0.0**: Environment variables are now required for sensitive configuration
- **1.0.0**: Real SSH keys must be stored in .env file, not committed to repository

## Migration Guide

### From 0.9.0 to 1.0.0

1. **Update configuration:**
   ```bash
   # Copy example environment file
   cp env.example .env
   
   # Edit .env with your sensitive configuration
   nano .env
   ```

2. **Generate demo keys:**
   ```bash
   ssh-keygen -t rsa -b 4096 -f keys/demo_id_rsa -N ""
   cp keys/demo_id_rsa.pub keys/authorized_keys_template
   ```

3. **Update requirements:**
   ```bash
   pip install -r requirements.txt
   ```

## Contributors

- **X3FV** - Initial development and security features
- **Security Contributors** - Vulnerability research and testing

## Acknowledgments

- **Paramiko** - SSH library
- **OpenSSH** - SSH protocol implementation
- **Security Researchers** - Vulnerability discovery and disclosure 