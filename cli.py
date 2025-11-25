#!/usr/bin/env python3
"""
CLI utilities for DNS Server Analyzer (argparse + startup banner).
"""

import argparse

from config import (
    INPUT_FILE,
    RECURSION_TEST_DOMAIN,
    LATENCY_TEST_DOMAIN,
    DNSSEC_TEST_DOMAIN,
    MALICIOUS_TEST_DOMAIN,
)
from utils import get_ist_timestamp


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for a single-run analyzer."""
    parser = argparse.ArgumentParser(
        description="DNS Server Analyzer - Single-run mode with per-server connections"
    )

    parser.add_argument(
        "-i",
        "--input",
        default=INPUT_FILE,
        help=f"Input JSON file (default: {INPUT_FILE})",
    )
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.1,
        help="Delay between servers in seconds (default: 0.1)",
    )

    return parser.parse_args()


def print_startup_banner(args: argparse.Namespace) -> None:
    """Print initial startup banner and configuration."""
    print(f"\n{'='*80}")
    print("DNS Server Analyzer - Single Run (Per-Server Connections)")
    print(f"Started at: {get_ist_timestamp()}")
    print("Mode: SINGLE RUN (triggered by systemd timer)")
    print("Test Domains:")
    print(f"  - Recursion: {RECURSION_TEST_DOMAIN}")
    print(f"  - Latency:   {LATENCY_TEST_DOMAIN}")
    print(f"  - DNSSEC:    {DNSSEC_TEST_DOMAIN}")
    print(f"  - Malicious: {MALICIOUS_TEST_DOMAIN}")
    print(f"{'='*80}\n")
