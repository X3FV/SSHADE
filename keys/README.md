# SSH Keys Directory

This directory is for storing SSH keys used by SSHade for persistence attacks.

## ⚠️ **IMPORTANT SECURITY NOTICE**

**NEVER commit real SSH keys to this repository!** This directory is for demonstration purposes only.

## Key Types

### Demo Keys (Safe for Public Repo)
- `demo_id_rsa` - Demo private key (for testing only)
- `demo_id_rsa.pub` - Demo public key (for testing only)
- `authorized_keys_template` - Template for authorized_keys file

### Real Keys (NOT for Public Repo)
- `id_rsa` - Real private key (add to .gitignore)
- `id_rsa.pub` - Real public key (add to .gitignore)
- `backdoor_keys` - Real backdoor keys (add to .gitignore)

## Generating Demo Keys

To generate demo keys for testing:

```bash
# Generate demo key pair
ssh-keygen -t rsa -b 4096 -f keys/demo_id_rsa -N ""

# Create authorized_keys template
cp keys/demo_id_rsa.pub keys/authorized_keys_template
```

## Using Real Keys (Local Development)

1. **Generate your own keys:**
   ```bash
   ssh-keygen -t rsa -b 4096 -f keys/id_rsa -N ""
   ```

2. **Add to .gitignore:**
   ```bash
   echo "keys/id_rsa" >> .gitignore
   echo "keys/id_rsa.pub" >> .gitignore
   echo "keys/backdoor_keys" >> .gitignore
   ```

3. **Use environment variables for sensitive data:**
   ```bash
   # Create .env file (not committed to repo)
   echo "SSH_PRIVATE_KEY_PATH=keys/id_rsa" > .env
   echo "SSH_PUBLIC_KEY_PATH=keys/id_rsa.pub" >> .env
   ```

## Security Best Practices

1. **Never commit real keys** - Always use demo keys for public repositories
2. **Use environment variables** - Store sensitive paths in .env files
3. **Rotate keys regularly** - Change keys periodically for security
4. **Use strong passphrases** - Protect private keys with strong passphrases
5. **Limit key permissions** - Set appropriate file permissions (600 for private keys)

## File Permissions

```bash
# Set correct permissions for SSH keys
chmod 600 keys/id_rsa          # Private key (read/write for owner only)
chmod 644 keys/id_rsa.pub      # Public key (readable by all)
chmod 644 keys/authorized_keys_template  # Template file
```

## Template Usage

The `authorized_keys_template` file shows the format for adding public keys to a target's authorized_keys file:

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... demo@sshade
```

## Environment Variables

Create a `.env` file (not committed to repo) with:

```bash
# SSH Key paths
SSH_PRIVATE_KEY_PATH=keys/id_rsa
SSH_PUBLIC_KEY_PATH=keys/id_rsa.pub

# Demo key paths (safe for public repo)
SSH_DEMO_PRIVATE_KEY_PATH=keys/demo_id_rsa
SSH_DEMO_PUBLIC_KEY_PATH=keys/demo_id_rsa.pub
```

## Testing with Demo Keys

For testing purposes, you can use the demo keys:

```bash
# Use demo keys for testing
python3 sshade.py -t 192.168.1.100 -m persist -k keys/demo_id_rsa.pub
```

**Remember:** Demo keys are for testing only and should not be used in real attacks! 