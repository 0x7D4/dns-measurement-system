#!/usr/bin/env python3
"""
Environment and preflight checks for DNS Server Analyzer.
"""

import os
import sys
from dotenv import load_dotenv

# Resolve .env relative to this file (same dir as main.py)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(CURRENT_DIR, ".env")

# Load environment variables eagerly so config.DB_CONFIG sees them
load_dotenv(dotenv_path=ENV_PATH, verbose=True)


def preflight_checks() -> None:
    """Check .env presence and required Python modules."""
    if not os.path.exists(ENV_PATH):
        print(f"⚠️  .env file not found at {ENV_PATH}")
        sys.exit(1)

    try:
        import dns  # noqa: F401
        import psycopg2  # noqa: F401
        import ipwhois  # noqa: F401
        import pytz  # noqa: F401
    except ImportError as e:
        print(f"❌ Missing required module: {e}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)


def verify_environment() -> None:
    """Verify runtime environment (DB credentials etc.)."""
    if not os.getenv("DB_PASSWORD"):
        print("❌ ERROR: DB_PASSWORD not found in .env")
        sys.exit(1)
