# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in SSHade, please follow these steps:

### 🚨 **IMPORTANT: DO NOT CREATE A PUBLIC ISSUE**

**Never report security vulnerabilities through public GitHub issues, as this could expose the vulnerability to attackers.**

### Reporting Process

1. **Email Security Details**
   - Send detailed information to: `security@yourdomain.com`
   - Include "SSHade Security Vulnerability" in the subject line

2. **Include the Following Information**
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if available)
   - Your contact information

3. **Response Timeline**
   - You will receive an acknowledgment within 48 hours
   - We will investigate and provide updates within 7 days
   - We will work with you to coordinate disclosure

4. **Responsible Disclosure**
   - Allow us time to fix the issue before public disclosure
   - We will credit you in the security advisory
   - We will coordinate the release of fixes and advisories

### What We Consider a Security Vulnerability

- **Authentication bypasses**
- **Remote code execution**
- **Privilege escalation**
- **Information disclosure**
- **Denial of service vulnerabilities**
- **Cryptographic weaknesses**
- **Configuration issues that could lead to compromise**

### What We Don't Consider a Security Issue

- **Feature requests**
- **Bug reports (non-security related)**
- **Usage questions**
- **Documentation issues**

## Security Best Practices

### For Users

1. **Always use on authorized systems only**
   - Never test against systems you don't own
   - Always get explicit permission before testing

2. **Keep the tool updated**
   - Regularly update to the latest version
   - Monitor security advisories

3. **Use secure configuration**
   - Use environment variables for sensitive data
   - Never commit real SSH keys to repositories
   - Use demo keys for testing

4. **Follow responsible disclosure**
   - Report vulnerabilities to us first
   - Allow time for fixes before public disclosure

### For Contributors

1. **Security review process**
   - All code changes require security review
   - Follow secure coding practices
   - Test thoroughly before submitting

2. **No sensitive data in commits**
   - Never commit real credentials or keys
   - Use environment variables for sensitive data
   - Follow the .gitignore guidelines

3. **Security testing**
   - Test your changes for security implications
   - Consider edge cases and attack vectors
   - Document security considerations

## Security Features

SSHade includes several security features:

- **Self-destruct mechanism** for secure cleanup
- **Time-based execution windows** for stealth operations
- **Background monitoring** for tamper detection
- **Secure file deletion** using shred and overwriting
- **Log clearing** capabilities
- **Fake reboot** simulation

## Contact Information

- **Security Email**: security@yourdomain.com
- **PGP Key**: [Add your PGP key fingerprint here]
- **Security Team**: [Add team contact information]

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors to security advisories will be credited appropriately.

## Legal Notice

This security policy is part of our commitment to responsible disclosure and security best practices. Users are responsible for ensuring they have proper authorization before using this tool. 