#!/usr/bin/env python3
"""
Core module for SSHade post-exploitation tool.
Contains self-destruct and monitoring functionality.
"""

from .destruct import self_destruct, SelfDestruct
from .guard import monitor, SSHadeGuard, start_guard

__all__ = [
    'self_destruct',
    'SelfDestruct', 
    'monitor',
    'SSHadeGuard',
    'start_guard'
]

# Auto-start guard when core module is imported
try:
    start_guard()
except Exception:
    pass 