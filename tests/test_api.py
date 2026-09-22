import sys
from pathlib import Path

# Ensure backend directory is in sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

# Re-export test suite from backend/tests/test_api.py
from backend.tests.test_api import *
