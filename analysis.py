#!/usr/bin/env python3

"""
Core analysis for DNS Server Analyzer.
Runs a single analysis cycle over all servers.
"""

import time
from datetime import datetime
from typing import List, Set, Optional

from database import PostgreSQLDatabase
from dns_checker import DNSChecker
from utils import (
    load_dns_servers,
    get_ist_timestamp,
    get_system_dns_servers,
    get_system_hostname,
    get_public_ip,
    get_dhcp_server_ips,  # NEW: bring back DHCP detection
)
from ipwhois import IPWhois  # for host public IP WHOIS


def analyze_server(
    server_ip: str,
    isp_related_servers: Set[str],
    system_hostname: str,
    public_ip: Optional[str],
) -> bool:
    """Analyze a single DNS server with isolated database connection."""
    db = None
    try:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Analyzing {server_ip}")

        is_isp_assigned = server_ip in isp_related_servers
        if is_isp_assigned:
            print(" 🌐 ISP/DHCP-related DNS server")

        # Open fresh DB connection for this server
        db = PostgreSQLDatabase()

        # Pass DB connection for WHOIS cache
        checker = DNSChecker(server_ip, db=db)
        result = checker.analyze(
            is_isp_assigned=is_isp_assigned,
            system_hostname=system_hostname,
            public_ip=public_ip,
        )

        # Store results
        db.log_queries(result.query_logs)
        db.save_server_result(result)

        # Display results
        status = "✅" if result.is_recursive else "❌"
        isp_marker = "🌐" if is_isp_assigned else " "
        reliability_marker = ""
        if result.test_reliability != "RELIABLE":
            reliability_marker = " ⚠️ "

        latency = f"{result.latency_ms:.2f}ms" if result.latency_ms else "N/A"
        dnssec = (
            "Yes"
            if result.dnssec_enabled
            else ("No" if result.dnssec_enabled is False else "N/A")
        )
        blocking = (
            "Yes"
            if result.malicious_blocking
            else ("No" if result.malicious_blocking is False else "N/A")
        )

        print(f" {status}{isp_marker} {server_ip:43s}{reliability_marker}")
        print(
            f" Latency: {latency:10s} | DNSSEC: {dnssec:3s} | "
            f"Blocking: {blocking:3s} | Org: {result.organization[:20]}"
        )

        if result.failure_reason:
            print(f" ⚠️ {result.failure_reason}")

        return True

    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f" ❌ Error analyzing {server_ip}: {str(e)[:60]}")
        return False
    finally:
        # Always close the connection, even on error
        if db:
            try:
                db.close()
            except Exception:
                pass


def get_whois_cache_stats() -> dict:
    """Get WHOIS cache statistics using a temporary connection."""
    db = None
    try:
        db = PostgreSQLDatabase()
        return db.get_whois_stats()
    except Exception as e:
        print(f"⚠️ Could not fetch WHOIS stats: {e}")
        return {"total_ips": 0, "cached_ips": 0, "missing_ips": 0}
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


# Record local measurement host identity (hostname, public IP, WHOIS/ASN)
def record_local_host_identity(system_hostname: str, public_ip: Optional[str]) -> None:
    """
    Resolve WHOIS / AS info for the local measurement host and store it
    in measurement_hosts. This is executed at the very start of a cycle.
    """
    if not public_ip:
        print("⚠️ Public IP is unknown, skipping host identity WHOIS.")
        return

    db = None    # will be PostgreSQLDatabase
    try:
        print(f"\n[HOST] Recording identity for {system_hostname} ({public_ip})")

        # RDAP WHOIS lookup for the host's public IP
        try:
            w = IPWhois(public_ip)
            # ipwhois.lookup_rdap(timeout=...) is not supported in your version,
            # so we call it without the timeout argument.
            rdap = w.lookup_rdap()
        except TypeError:
            # Fallback if library signature is older
            rdap = w.lookup_rdap()
        except Exception as e:
            print(f"  [HOST] WHOIS lookup failed: {e}")
            rdap = {}

        org = (
            (rdap.get("network") or {}).get("name")
            or rdap.get("asn_description")
            or "N/A"
        )
        asn = rdap.get("asn") or "N/A"
        asn_desc = rdap.get("asn_description") or "N/A"
        country = rdap.get("asn_country_code") or "N/A"

        db = PostgreSQLDatabase()
        db.upsert_measurement_host(
            system_hostname=system_hostname,
            public_ip=public_ip,
            organization=org,
            asn=asn,
            asn_description=asn_desc,
            country=country,
        )

    except Exception as e:
        print(f"⚠️ Could not record host identity: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass


def run_analysis_cycle(dns_servers: List[str], delay: float) -> None:
    """Run one complete analysis cycle (single run)."""
    system_hostname = get_system_hostname()
    public_ip = get_public_ip()
    system_dns_servers = get_system_dns_servers()
    dhcp_servers = get_dhcp_server_ips()
    isp_related_servers = system_dns_servers | dhcp_servers

    # First action – record local host identity in measurement_hosts
    record_local_host_identity(system_hostname, public_ip)

    print(f"\n{'='*80}")
    print(f"Cycle Started: {get_ist_timestamp()}")
    print(f"💻 System: {system_hostname} | 🌍 Public IP: {public_ip or 'N/A'}")
    print(
        f"📋 Analyzing {len(dns_servers)} servers "
        f"(including {len(isp_related_servers)} ISP/DHCP-related)"
    )
    print(f"{'='*80}")

    # WHOIS cache stats
    whois_stats = get_whois_cache_stats()
    print("\n📊 WHOIS Cache Stats:")
    print(f" Total IPs: {whois_stats['total_ips']}")
    print(f" Cached: {whois_stats['cached_ips']}")
    print(f" Missing: {whois_stats['missing_ips']}")
    if whois_stats["missing_ips"] > 0:
        print(
            " ℹ️ Run 'python whois.py --batch 50' to populate missing WHOIS data"
        )
    print()

    if system_dns_servers:
        print(f"System DNS servers: {', '.join(sorted(system_dns_servers))}")
    if dhcp_servers:
        print(f"DHCP server IPs:   {', '.join(sorted(dhcp_servers))}")
    print()

    start_time = time.time()
    successful = 0
    failed = 0

    for idx, server_ip in enumerate(dns_servers, 1):
        if analyze_server(server_ip, isp_related_servers, system_hostname, public_ip):
            successful += 1
        else:
            failed += 1

        # Progress updates
        if idx % 10 == 0 or idx == len(dns_servers):
            elapsed = time.time() - start_time
            avg_time = elapsed / idx
            remaining = (len(dns_servers) - idx) * avg_time
            print(
                f"\n Progress: {idx}/{len(dns_servers)} | "
                f"Success: {successful} | Failed: {failed} | "
                f"ETA: {remaining:.0f}s"
            )

        # Delay between servers
        if delay > 0 and idx < len(dns_servers):
            time.sleep(delay)

    elapsed_time = time.time() - start_time
    print(f"\n{'='*80}")
    print(f"Cycle Complete: {get_ist_timestamp()}")
    print(
        f"Success: {successful}/{len(dns_servers)} | "
        f"Failed: {failed} | Time: {elapsed_time:.2f}s"
    )
    print(f"{'='*80}\n")


def load_all_dns_servers(input_file: str) -> List[str]:
    """Load DNS servers from file and prepend system/DHCP DNS servers."""
    try:
        dns_servers = load_dns_servers(input_file)
        print(f"✅ Loaded {len(dns_servers)} DNS server IPs")

        system_dns = get_system_dns_servers()
        dhcp_dns = get_dhcp_server_ips()

        added_system: List[str] = []
        for ip in system_dns:
            if ip not in dns_servers:
                dns_servers.insert(0, ip)
                added_system.append(ip)

        added_dhcp: List[str] = []
        for ip in dhcp_dns:
            if ip not in dns_servers:
                dns_servers.insert(0, ip)
                added_dhcp.append(ip)

        if added_system:
            print(f"➕ Auto-added {len(added_system)} system DNS: {', '.join(added_system)}")
        if added_dhcp:
            print(f"➕ Auto-added {len(added_dhcp)} DHCP server IPs: {', '.join(added_dhcp)}")

        print(f"📋 Total servers: {len(dns_servers)}\n")
        return dns_servers

    except Exception as e:
        print(f"❌ Failed to load servers: {e}")
        raise
