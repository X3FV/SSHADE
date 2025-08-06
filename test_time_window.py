#!/usr/bin/env python3
from sshade import SSHade
from datetime import datetime

def test_time_window():
    """Test the time window functionality"""
    print("Testing time window functionality...")
    
    # Create SSHade instance
    tool = SSHade()
    
    # Test 1: Default time window (should always allow)
    print(f"\nTest 1: Default time window (0-23)")
    tool.set_time_window(0, 23)
    print(f"Current hour: {datetime.now().hour}")
    print(f"Within window: {tool.is_within_time_window()}")
    
    # Test 2: Current hour window (should always allow)
    current_hour = datetime.now().hour
    print(f"\nTest 2: Current hour window ({current_hour}-{current_hour})")
    tool.set_time_window(current_hour, current_hour)
    print(f"Within window: {tool.is_within_time_window()}")
    
    # Test 3: Impossible window (should always deny)
    print(f"\nTest 3: Impossible window (should deny)")
    tool.set_time_window((current_hour + 1) % 24, (current_hour + 1) % 24)
    print(f"Current hour: {datetime.now().hour}")
    print(f"Within window: {tool.is_within_time_window()}")
    
    # Test 4: Wrap-around window
    print(f"\nTest 4: Wrap-around window (23-1)")
    tool.set_time_window(23, 1)
    print(f"Current hour: {datetime.now().hour}")
    print(f"Within window: {tool.is_within_time_window()}")

if __name__ == "__main__":
    test_time_window()
