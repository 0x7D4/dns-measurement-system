#!/usr/bin/env python3

"""
DNS Server Analyzer - Thin entrypoint.

All heavy lifting is done in environment.py, cli.py, and analysis.py.
"""

from environment import preflight_checks, verify_environment
from cli import parse_args, print_startup_banner
from analysis import load_all_dns_servers, run_analysis_cycle


def main() -> None:
    """Main entry point that just wires together helpers."""
    # Environment and dependency checks
    preflight_checks()
    verify_environment()

    # CLI parsing and banner
    args = parse_args()
    print_startup_banner(args)

    # Load servers and run a single analysis cycle
    dns_servers = load_all_dns_servers(args.input)
    run_analysis_cycle(dns_servers, delay=args.delay)


if __name__ == "__main__":
    main()
