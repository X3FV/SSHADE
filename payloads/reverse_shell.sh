#!/bin/bash
# Simple reverse shell script for persistence
# This would connect back to the attacker in a real implementation

# For demonstration purposes, we'll just create a marker file
echo "Reverse shell executed at $(date)" > /tmp/reverse_shell_marker
