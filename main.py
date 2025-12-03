#!/usr/bin/env python3
"""
DNS Server Analyzer - Main Entry Point
Distributed measurement and analysis of DNS resolvers
"""

import sys
import time
from analysis import run_analysis_cycle, load_all_dns_servers
from cli import parse_args, print_startup_banner


def main():
    """Main entry point for DNS Server Analyzer."""
    try:
        # Print startup banner (no arguments)
        print_startup_banner()

        # Parse command-line arguments
        args = parse_args()

        # Load DNS servers from input file
        dns_servers = load_all_dns_servers(args.input)

        if args.once:
            # Run once and exit
            print("🔄 Running single analysis cycle...")
            run_analysis_cycle(dns_servers, args.delay)
            print("✅ Analysis complete. Exiting.")
            sys.exit(0)
        else:
            # Continuous mode with timer
            print(f"🔁 Running continuous analysis (interval: {args.interval}s)")
            print("Press Ctrl+C to stop\n")

            cycle_count = 1
            while True:
                print(f"\n{'#' * 80}")
                print(f"# Cycle {cycle_count}")
                print(f"{'#' * 80}\n")

                run_analysis_cycle(dns_servers, args.delay)

                cycle_count += 1
                print(f"\n⏸️  Waiting {args.interval} seconds until next cycle...")
                print(f"   (Press Ctrl+C to stop)")

                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user. Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
