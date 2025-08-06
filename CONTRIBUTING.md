# Contributing to SSHade

Thank you for your interest in contributing to SSHade! This document provides guidelines for contributing to the project safely and responsibly.

## 🛡️ **Security First**

**IMPORTANT**: SSHade is a security testing tool. All contributions must follow security best practices:

- **Never commit real credentials, keys, or sensitive data**
- **Always use demo/test data for examples**
- **Follow responsible disclosure practices**
- **Test thoroughly before submitting**

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful and inclusive**
- **Focus on constructive feedback**
- **Respect privacy and security**
- **Follow responsible disclosure practices**

## How Can I Contribute?

### 🐛 **Reporting Bugs**

1. **Check existing issues** - Search for similar issues first
2. **Use the bug report template** - Provide detailed information
3. **Include reproduction steps** - Make it easy to reproduce
4. **Include system information** - OS, Python version, etc.

### 💡 **Suggesting Features**

1. **Check existing feature requests** - Avoid duplicates
2. **Provide clear use cases** - Explain why the feature is needed
3. **Consider security implications** - How does it affect security?
4. **Include implementation ideas** - If you have suggestions

### 🔧 **Code Contributions**

#### Before You Start

1. **Fork the repository**
2. **Create a feature branch** - `git checkout -b feature/amazing-feature`
3. **Set up development environment** - Install dependencies
4. **Read the codebase** - Understand the existing structure

#### Development Guidelines

1. **Follow Python style guidelines**
   - Use PEP 8 style guide
   - Use meaningful variable names
   - Add proper docstrings

2. **Security considerations**
   - Never hardcode credentials
   - Use environment variables for sensitive data
   - Validate all inputs
   - Handle errors gracefully

3. **Testing requirements**
   - Add tests for new features
   - Ensure existing tests pass
   - Test edge cases and error conditions

4. **Documentation**
   - Update README.md if needed
   - Add inline comments for complex logic
   - Update configuration examples

#### Submission Process

1. **Test your changes thoroughly**
   ```bash
   # Run basic tests
   python3 -m pytest tests/
   
   # Test your specific feature
   python3 sshade.py --help
   ```

2. **Check for sensitive data**
   ```bash
   # Search for potential sensitive data
   grep -r "password\|key\|secret\|token" . --exclude-dir=.git
   ```

3. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add amazing feature: brief description"
   git push origin feature/amazing-feature
   ```

4. **Create a Pull Request**
   - Use the PR template
   - Describe your changes clearly
   - Link any related issues

## Development Setup

### Prerequisites

- Python 3.7+
- Git
- Basic understanding of SSH and security concepts

### Local Development

1. **Clone your fork**
   ```bash
   git clone https://github.com/yourusername/sshade.git
   cd sshade
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

4. **Generate demo keys**
   ```bash
   ssh-keygen -t rsa -b 4096 -f keys/demo_id_rsa -N ""
   cp keys/demo_id_rsa.pub keys/authorized_keys_template
   ```

### Testing

```bash
# Run basic functionality tests
python3 sshade.py --help

# Test specific modules
python3 attacks/test_rootkit.py

# Test configuration loading
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

## Security Guidelines

### ✅ **Do's**

- Use demo keys and test data
- Implement proper input validation
- Add error handling for edge cases
- Follow secure coding practices
- Test thoroughly before submitting
- Use environment variables for sensitive data

### ❌ **Don'ts**

- Never commit real credentials or keys
- Don't hardcode sensitive information
- Don't bypass security measures
- Don't submit untested code
- Don't ignore error conditions
- Don't use real targets in examples

## Code Style

### Python Style

```python
# Good
def connect_ssh(host: str, username: str, password: str) -> bool:
    """Establish SSH connection with password authentication.
    
    Args:
        host: Target hostname or IP address
        username: SSH username
        password: SSH password
        
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        # Implementation here
        return True
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        return False

# Bad
def ssh(h, u, p):
    # No docstring, unclear variable names
    return True
```

### Configuration Style

```yaml
# Good - Clear and documented
connection:
  default_port: 22           # Default SSH port
  timeout: 15                # Connection timeout in seconds

# Bad - Unclear purpose
conn:
  port: 22
  t: 15
```

## Review Process

1. **Automated checks** - CI/CD will run tests
2. **Security review** - All code is reviewed for security issues
3. **Functionality review** - Code is tested for functionality
4. **Documentation review** - Documentation is updated as needed

## Release Process

1. **Version bump** - Update version numbers
2. **Changelog update** - Document changes
3. **Security review** - Final security check
4. **Release notes** - Create detailed release notes

## Getting Help

- **GitHub Issues** - For bugs and feature requests
- **Discussions** - For questions and general discussion
- **Security Email** - For security vulnerabilities (see SECURITY.md)

## Recognition

Contributors will be recognized in:
- Release notes
- Contributors list
- Security advisories (for security contributions)

## Legal Notice

By contributing to SSHade, you agree that your contributions will be licensed under the MIT License. You also agree to follow responsible disclosure practices and respect the security-focused nature of this project.

Thank you for contributing to SSHade responsibly! 🛡️ 