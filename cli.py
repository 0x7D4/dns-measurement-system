import argparse
import sys
from datetime import datetime
from config import INPUT_FILE, DEFAULT_DELAY


def get_utc_timestamp() -> str:
    """Get current timestamp in UTC."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def print_startup_banner():
    """Print ASCII art startup banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║              DNS Server Analyzer - v2.0                      ║
    ║         Distributed Measurement & Analysis System            ║
    ║                                                              ║
    ║  Features:                                                   ║
    ║   • Recursion Detection                                      ║
    ║   • Latency Measurement                                      ║
    ║   • DNSSEC Validation                                        ║
    ║   • Malicious Domain Blocking                                ║
    ║   • WHOIS/ASN Enrichment                                     ║
    ║   • Cache TTL Analysis                                       ║
    ║   • Distributed Anchor Tracking                              ║
    ║   • DNS Capability Detection                                 ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f"    Started: {get_utc_timestamp()}")
    print()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="DNS Server Analyzer - Measure and analyze DNS resolver performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default=INPUT_FILE,
        help=f"Input JSON file with DNS server IPs (default: {INPUT_FILE})",
    )

    parser.add_argument(
        "--delay",
        "-d",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between server tests in seconds (default: {DEFAULT_DELAY})",
    )

    return parser.parse_args()
