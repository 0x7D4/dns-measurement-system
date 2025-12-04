#!/usr/bin/env python3
"""
Core analysis for DNS Server Analyzer.
Runs a single analysis cycle over all servers.
All timestamps use UTC.
"""

import time
from datetime import datetime
from typing import List, Set, Optional
from ipaddress import ip_address

from database import PostgreSQLDatabase
from dns_checker import DNSChecker
from utils import (
    load_dns_servers,
    get_system_dns_servers,
    get_system_hostname,
    get_public_ip,
    get_dhcp_server_ips,
)
from ipwhois import IPWhois

# HARDCODED FILTER: IPs to exclude from analysis
EXCLUDED_IPS = {"172.31.31.31"}

def get_utc_timestamp() -> str:
    """Get current timestamp in UTC."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def analyze_server(
    server_ip: str,
    isp_related_servers: Set[str],
    system_hostname: str,
    public_ip: Optional[str],
) -> bool:
    """Analyze a single DNS server with isolated database connection."""
    
    # SKIP EXCLUDED IPs
    if server_ip in EXCLUDED_IPS:
        print(f"[{datetime.utcnow().strftime('%H:%M:%S')} UTC] 🚫 Skipping excluded IP: {server_ip}")
        return True  # Return True to not count as failed
    
    db = None
    try:
        print(f"\n[{datetime.utcnow().strftime('%H:%M:%S')} UTC] Analyzing {server_ip}")
        is_isp_assigned = server_ip in isp_related_servers
        if is_isp_assigned:
            print("   🌐 ISP/DHCP-related DNS server")

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
        isp_marker = "🌐" if is_isp_assigned else "  "
        reliability_marker = ""
        if result.test_reliability != "RELIABLE":
            reliability_marker = " ⚠️  "

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

        print(f"  {status}{isp_marker} {server_ip:43s}{reliability_marker}")
        print(
            f"     Latency: {latency:10s} | DNSSEC: {dnssec:3s} | "
            f"Blocking: {blocking:3s} | Org: {result.organization[:20]}"
        )

        if result.failure_reason:
            print(f"     ⚠️  {result.failure_reason}")

        return True

    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"  ❌ Error analyzing {server_ip}: {str(e)[:60]}")
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

def enrich_whois_data_for_servers(dns_servers: List[str], max_lookups: int = 100) -> int:
    """
    Pre-enrich WHOIS data for DNS servers before analysis.
    Only processes IPs that don't have WHOIS data yet.
    
    Args:
        dns_servers: List of DNS server IPs to check
        max_lookups: Maximum number of WHOIS lookups per run (default: 100)
    
    Returns:
        Number of IPs enriched in this run
    """
    db = None
    try:
        db = PostgreSQLDatabase()

        # Check which of our DNS servers need WHOIS data
        ips_needing_whois = []
        private_ips_saved = 0

        for ip in dns_servers:
            # Skip private IPs - save placeholder immediately
            try:
                if ip_address(ip).is_private:
                    print(f"   Skipping private IP {ip}")
                    # Save placeholder for private IPs so we don't keep trying
                    db.save_whois_cache(
                        server_ip=ip,
                        organization="Private Network",
                        asn="N/A",
                        asn_description="Private/Reserved IP",
                        country="N/A"
                    )
                    private_ips_saved += 1
                    continue
            except ValueError:
                pass

            # Check if already cached
            cached = db.get_whois_cache(ip)
            if not cached:
                ips_needing_whois.append(ip)

        if private_ips_saved > 0:
            print(f"   Saved {private_ips_saved} private IPs with placeholder data")

        if not ips_needing_whois:
            print("✅ All DNS servers already have WHOIS data cached.")
            return private_ips_saved

        # Limit to max_lookups per run
        ips_to_process = ips_needing_whois[:max_lookups]
        remaining = len(ips_needing_whois) - len(ips_to_process)

        print("\n" + "=" * 80)
        print(f"WHOIS Pre-Enrichment: Processing {len(ips_to_process)} IPs")
        if remaining > 0:
            print(f"   {remaining} IPs will be processed in next run(s)")
        print("=" * 80)

        success_count = 0
        failed_count = 0

        for idx, ip in enumerate(ips_to_process, 1):
            try:
                print(f"[{idx}/{len(ips_to_process)}] {ip}: ", end="", flush=True)

                # Perform WHOIS lookup
                whois = IPWhois(ip)
                try:
                    rdap = whois.lookup_rdap()
                except TypeError:
                    # Fallback for older ipwhois versions
                    rdap = whois.lookup_rdap()
                except Exception:
                    # Fallback to legacy WHOIS
                    rdap = whois.lookup_whois()

                # Extract data
                org = rdap.get("network", {}).get("name") or rdap.get("asn_description") or "Unknown"
                asn = rdap.get("asn") or "Unknown"
                asn_desc = rdap.get("asn_description") or "Unknown"
                country = rdap.get("asn_country_code") or "Unknown"

                # Save to cache
                db.save_whois_cache(
                    server_ip=ip,
                    organization=org,
                    asn=asn,
                    asn_description=asn_desc,
                    country=country
                )

                print(f"✅ OK | {org[:30]} | {asn} | {country}")
                success_count += 1

                # Rate limiting (1 second delay to avoid being blocked)
                if idx < len(ips_to_process):
                    time.sleep(1.0)

            except Exception as e:
                print(f"❌ FAILED | {str(e)[:50]}")
                # Save as "Lookup Failed" so we don't retry immediately
                try:
                    db.save_whois_cache(
                        server_ip=ip,
                        organization="Lookup Failed",
                        asn="Unknown",
                        asn_description=str(e)[:100],
                        country="Unknown"
                    )
                except Exception as save_err:
                    print(f"   ⚠️ Could not save error to cache: {save_err}")
                failed_count += 1

        print("-" * 80)
        print(f"Enrichment Complete: {success_count} successful, {failed_count} failed")
        if remaining > 0:
            print(f"Remaining for next run: {remaining} IPs")
        print("=" * 80 + "\n")

        return success_count + private_ips_saved

    except Exception as e:
        print(f"❌ WHOIS enrichment error: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def record_localhost_identity(system_hostname: str, public_ip: Optional[str]) -> None:
    """
    Resolve WHOIS/AS info for the local measurement host and store it in measurement_hosts.
    Also checks if the anchor's public IP supports DNS queries.
    This is executed at the very start of a cycle.
    """
    if not public_ip:
        print("⚠️ Public IP is unknown, skipping host identity WHOIS.")
        return

    db = None
    try:
        print(f"\n[HOST] Recording identity for {system_hostname} ({public_ip})")

        # 1. Check DNS capability
        print(f"[HOST] Testing DNS capability on {public_ip}...")
        dns_capability = DNSChecker.check_dns_capability(public_ip, timeout=3)

        if dns_capability["is_dns_server"]:
            print(f"   ✓ DNS server detected | Latency: {dns_capability['latency_ms']:.1f}ms | "
                  f"Recursion: {'Yes' if dns_capability['supports_recursion'] else 'No'}")
        else:
            print(f"   ✗ No DNS service detected | Reason: {dns_capability['error'] or 'No response'}")

        # 2. WHOIS lookup for the host's public IP
        try:
            w = IPWhois(public_ip)
            try:
                rdap = w.lookup_rdap()
            except TypeError:
                # Fallback if library signature is older
                rdap = w.lookup_rdap()
        except Exception as e:
            print(f"   [HOST] WHOIS lookup failed: {e}")
            rdap = {}

        org = (
            (rdap.get("network") or {}).get("name")
            or rdap.get("asn_description")
            or "N/A"
        )
        asn = rdap.get("asn") or "N/A"
        asn_desc = rdap.get("asn_description") or "N/A"
        country = rdap.get("asn_country_code") or "N/A"

        # 3. Store in database
        db = PostgreSQLDatabase()
        db.upsert_measurement_host(
            system_hostname=system_hostname,
            public_ip=public_ip,
            organization=org,
            asn=asn,
            asn_description=asn_desc,
            country=country,
            supports_dns=dns_capability["is_dns_server"],
            supports_recursion=dns_capability["supports_recursion"],
            dns_latency_ms=dns_capability["latency_ms"]
        )

        print(f"   [HOST] Stored: {org} | ASN {asn} | {country} | "
              f"DNS: {'Yes' if dns_capability['is_dns_server'] else 'No'}")

    except Exception as e:
        print(f"⚠️ Could not record host identity: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def run_analysis_cycle(dns_servers: List[str], delay: float) -> None:
    """
    Run one complete analysis cycle (single run).
    Automatically enriches WHOIS data before analysis (up to 100 IPs per run).
    """
    system_hostname = get_system_hostname()
    public_ip = get_public_ip()
    system_dns_servers = get_system_dns_servers()
    dhcp_servers = get_dhcp_server_ips()
    isp_related_servers = system_dns_servers | dhcp_servers

    # FILTER OUT EXCLUDED IPs from the server list
    original_count = len(dns_servers)
    dns_servers = [ip for ip in dns_servers if ip not in EXCLUDED_IPS]
    excluded_count = original_count - len(dns_servers)
    
    if excluded_count > 0:
        print(f"\n🚫 Excluded {excluded_count} IP(s) from analysis: {', '.join(EXCLUDED_IPS)}\n")

    # Record local host identity
    record_localhost_identity(system_hostname, public_ip)

    print("=" * 80)
    print(f"Cycle Started: {get_utc_timestamp()}")
    print(f"💻 System: {system_hostname} | 🌍 Public IP: {public_ip or 'N/A'}")
    print(
        f"📋 Analyzing {len(dns_servers)} servers "
        f"(including {len(isp_related_servers)} ISP/DHCP-related)"
    )
    print("=" * 80)

    # WHOIS cache stats (from analysis results - for info only)
    whois_stats_before = get_whois_cache_stats()
    print("\n📊 WHOIS Cache Stats (from analysis results):")
    print(f"   Total IPs in results table: {whois_stats_before['total_ips']}")
    print(f"   Cached: {whois_stats_before['cached_ips']}")
    print(f"   Missing: {whois_stats_before['missing_ips']}")

    # ALWAYS check dns_servers list for missing WHOIS (not based on stats above)
    print(f"\n🔍 WHOIS data for {len(dns_servers)} DNS servers...")
    enriched_count = enrich_whois_data_for_servers(dns_servers, max_lookups=100)

    if enriched_count > 0:
        print(f"✅ Successfully enriched {enriched_count} IPs with WHOIS data\n")

    if system_dns_servers:
        print(f"System DNS servers: {', '.join(sorted(system_dns_servers))}")
    if dhcp_servers:
        print(f"DHCP server IPs: {', '.join(sorted(dhcp_servers))}")
    print()

    # Start DNS analysis
    start_time = time.time()
    successful = 0
    failed = 0

    for idx, server_ip in enumerate(dns_servers, 1):
        if analyze_server(server_ip, isp_related_servers, system_hostname, public_ip):
            successful += 1
        else:
            failed += 1

        # Progress updates
        if (idx % 10 == 0) or (idx == len(dns_servers)):
            elapsed = time.time() - start_time
            avg_time = elapsed / idx
            remaining = (len(dns_servers) - idx) * avg_time
            print(
                f"\n📊 Progress: {idx}/{len(dns_servers)} | "
                f"Success: {successful} | Failed: {failed} | "
                f"ETA: {remaining:.0f}s"
            )

        # Delay between servers
        if delay > 0 and idx < len(dns_servers):
            time.sleep(delay)

    elapsed_time = time.time() - start_time
    print(f"\n{'=' * 80}")
    print(f"Cycle Complete: {get_utc_timestamp()}")
    print(
        f"Success: {successful}/{len(dns_servers)} | "
        f"Failed: {failed} | Time: {elapsed_time:.2f}s"
    )
    print(f"{'=' * 80}\n")

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
