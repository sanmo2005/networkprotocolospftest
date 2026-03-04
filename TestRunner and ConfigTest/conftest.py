# conftest.py - pytest configuration
# All tests are unittest.TestCase subclasses and auto-discovered by pytest

import sys
import os

# Ensure ospf_lib is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
