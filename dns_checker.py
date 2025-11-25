# dns_checker.py

import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import dns.rcode
import dns.exception
import time
import subprocess
import platform
from typing import Optional, List, Tuple
from ipaddress import ip_address

from ipwhois import IPWhois  # currently only used by separate WHOIS script
from models import DNSQueryLog, ServerResult
from config import (
    DNS_TIMEOUT,
    RECURSION_TEST_DOMAIN,
    LATENCY_TEST_DOMAIN,
    DNSSEC_TEST_DOMAIN,
    MALICIOUS_TEST_DOMAIN,
    TRACEROUTE_TEST_DOMAIN,  # now unused but kept for compatibility
    CACHE_TTL_TEST_DOMAIN,
)
import datetime


class DNSChecker:
    def __init__(self, server_ip: str, db=None):
        self.server_ip = server_ip
        self.query_logs: List[DNSQueryLog] = []
        self.db = db  # Database connection for WHOIS cache
        self.system_hostname = "unknown"  # set in analyze()

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------

    def _safe_flags_to_str(self, flags: int) -> str:
        try:
            parts = []
            if flags & dns.flags.AA:
                parts.append("AA")
            if flags & dns.flags.TC:
                parts.append("TC")
            if flags & dns.flags.RD:
                parts.append("RD")
            if flags & dns.flags.RA:
                parts.append("RA")
            if flags & dns.flags.AD:
                parts.append("AD")
            if flags & dns.flags.CD:
                parts.append("CD")
            return f"{hex(flags)} ({'|'.join(parts) if parts else 'NONE'})"
        except Exception:
            return str(flags)

    def _answer_to_str(self, response) -> Optional[str]:
        try:
            if response and response.answer:
                return "\n".join([rrset.to_text() for rrset in response.answer])
            return None
        except Exception:
            return None

    def _extract_ttl(self, response) -> Optional[int]:
        """Extract TTL from DNS response answer section."""
        try:
            if response and response.answer:
                return response.answer[0].ttl
            return None
        except Exception:
            return None

    def _is_private_ip(self) -> bool:
        """Return True if server_ip is RFC1918/private."""
        try:
            return ip_address(self.server_ip).is_private
        except ValueError:
            return False

    def log_query(
        self,
        query_type: str,
        query_name: str,
        test_type: str,
        response,
        response_time_ms: Optional[float],
        query_flags: str = "",
    ):
        """Log DNS query details including TTL."""
        ttl = self._extract_ttl(response) if response else None

        log = DNSQueryLog(
            server_ip=self.server_ip,
            system_hostname=self.system_hostname,
            query_type=query_type,
            query_name=query_name,
            query_flags=query_flags,
            response_rcode=dns.rcode.to_text(response.rcode()) if response else "TIMEOUT",
            response_flags=self._safe_flags_to_str(response.flags) if response else "N/A",
            response_answer=self._answer_to_str(response),
            response_ttl=ttl,
            response_time_ms=round(response_time_ms, 3)
            if response_time_ms is not None
            else None,
            timestamp=datetime.datetime.utcnow(),
            test_type=test_type,
        )
        self.query_logs.append(log)

    def log_traceroute(
        self,
        dest: str,
        status: str,
        output: str,
        elapsed_ms: Optional[float],
    ):
        """Log traceroute output as a special test into dns_query_logs."""
        log = DNSQueryLog(
            server_ip=self.server_ip,
            system_hostname=self.system_hostname,
            query_type="TRACE",
            query_name=dest,
            query_flags="TRACEROUTE",
            response_rcode=status,
            response_flags="",
            response_answer=output,
            response_ttl=None,
            response_time_ms=round(elapsed_ms, 3) if elapsed_ms is not None else None,
            timestamp=datetime.datetime.utcnow(),
            test_type="traceroute",
        )
        self.query_logs.append(log)

    def _udp_query(self, qname: str, qtype, want_dnssec: bool = False, set_rd: bool = False):
        """Helper to build and send a UDP DNS query."""
        query = dns.message.make_query(qname, qtype, want_dnssec=want_dnssec)
        if set_rd:
            query.flags |= dns.flags.RD
        start = time.time()
        resp = dns.query.udp(query, self.server_ip, timeout=DNS_TIMEOUT)
        rtt_ms = (time.time() - start) * 1000
        return query, resp, rtt_ms

    # ----------------------------------------------------------------------
    # DNS checks with detailed logging
    # ----------------------------------------------------------------------

    def check_recursion(self) -> Tuple[bool, bool, Optional[float], str]:
        """Check if server is recursive - returns (is_recursive, ra_flag_set, rtt, rcode)."""
        print(f"    [STEP] Recursion check for {self.server_ip} (domain={RECURSION_TEST_DOMAIN})")
        try:
            query, response, rtt = self._udp_query(
                RECURSION_TEST_DOMAIN,
                dns.rdatatype.A,
                want_dnssec=False,
                set_rd=True,
            )
            ra_flag_set = bool(response.flags & dns.flags.RA)
            rcode = dns.rcode.to_text(response.rcode())
            is_recursive = (
                ra_flag_set
                and bool(response.answer)
                and response.rcode() == dns.rcode.NOERROR
            )
            self.log_query("A", RECURSION_TEST_DOMAIN, "recursion", response, rtt, "RD")
            print(
                f"      result: recursive={is_recursive}, RA_flag={ra_flag_set}, "
                f"rcode={rcode}, rtt_ms={rtt:.3f}"
            )
            return is_recursive, ra_flag_set, rtt, rcode
        except dns.exception.Timeout:
            self.log_query(
                "A",
                RECURSION_TEST_DOMAIN,
                "recursion",
                None,
                DNS_TIMEOUT * 1000,
                "RD",
            )
            print("      result: TIMEOUT")
            return False, False, None, "TIMEOUT"
        except Exception:
            self.log_query("A", RECURSION_TEST_DOMAIN, "recursion", None, None, "RD")
            print("      result: ERROR (exception during recursion check)")
            return False, False, None, "ERROR"

    def check_latency(self) -> Tuple[Optional[float], str]:
        """Measure latency - returns (latency_ms, rcode)."""
        print(f"    [STEP] Latency check for {self.server_ip} (domain={LATENCY_TEST_DOMAIN})")
        try:
            query, response, rtt = self._udp_query(
                LATENCY_TEST_DOMAIN,
                dns.rdatatype.A,
                set_rd=True,
            )
            rcode = dns.rcode.to_text(response.rcode())
            self.log_query("A", LATENCY_TEST_DOMAIN, "latency", response, rtt)
            rtt_str = f"{rtt:.3f}" if response else "N/A"
            print(f"      result: rcode={rcode}, rtt_ms={rtt_str}")
            return (rtt if response else None), rcode
        except dns.exception.Timeout:
            self.log_query(
                "A",
                LATENCY_TEST_DOMAIN,
                "latency",
                None,
                DNS_TIMEOUT * 1000,
            )
            print("      result: TIMEOUT")
            return None, "TIMEOUT"
        except Exception:
            self.log_query("A", LATENCY_TEST_DOMAIN, "latency", None, None)
            print("      result: ERROR (exception during latency check)")
            return None, "ERROR"

    def get_whois_info(self) -> Tuple[str, str, str, str]:
        """
        Get WHOIS information for this server IP.

        Current behavior:
        - Uses database cache (whois_cache) if available.
        - Does not perform live RDAP lookups here.
        """
        if self.db:
            cached = self.db.get_whois_cache(self.server_ip)
            if cached:
                org, asn, asn_desc, country = cached
                print(
                    "    [STEP] WHOIS (cache): "
                    f"org={org}, asn={asn}, asn_desc={asn_desc}, country={country}"
                )
                return cached

        print("    [STEP] WHOIS: no cached entry, returning N/A placeholders")
        return "N/A", "N/A", "N/A", "N/A"

    def check_dnssec(self) -> Tuple[bool, bool, str, Optional[float]]:
        """Check DNSSEC validation using AD flag."""
        print(f"    [STEP] DNSSEC check for {self.server_ip} (domain={DNSSEC_TEST_DOMAIN})")
        try:
            query, response, rtt = self._udp_query(
                DNSSEC_TEST_DOMAIN,
                dns.rdatatype.A,
                want_dnssec=True,
                set_rd=True,
            )
            ad_flag_set = bool(response.flags & dns.flags.AD)
            dnssec_enabled = ad_flag_set and response.rcode() == dns.rcode.NOERROR
            rcode = dns.rcode.to_text(response.rcode())
            self.log_query(
                "A",
                DNSSEC_TEST_DOMAIN,
                "dnssec",
                response,
                rtt,
                query_flags="DO",
            )
            print(
                f"      result: dnssec_enabled={dnssec_enabled}, AD_flag={ad_flag_set}, "
                f"rcode={rcode}, rtt_ms={rtt:.3f}"
            )
            return dnssec_enabled, ad_flag_set, rcode, rtt
        except dns.exception.Timeout:
            self.log_query(
                "A",
                DNSSEC_TEST_DOMAIN,
                "dnssec",
                None,
                DNS_TIMEOUT * 1000,
                query_flags="DO",
            )
            print("      result: TIMEOUT")
            return False, False, "TIMEOUT", None
        except Exception:
            self.log_query(
                "A",
                DNSSEC_TEST_DOMAIN,
                "dnssec",
                None,
                None,
                query_flags="DO",
            )
            print("      result: ERROR (exception during DNSSEC check)")
            return False, False, "ERROR", None

    def check_malicious_blocking(self) -> Tuple[bool, str, Optional[float]]:
        """Check if server blocks malicious domains."""
        print(
            f"    [STEP] Malicious-domain check for {self.server_ip} "
            f"(domain={MALICIOUS_TEST_DOMAIN})"
        )
        try:
            query, response, rtt = self._udp_query(
                MALICIOUS_TEST_DOMAIN,
                dns.rdatatype.A,
                set_rd=True,
            )
            rcode = response.rcode()
            rcode_text = dns.rcode.to_text(rcode)
            blocks_malicious = (
                rcode in [dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL, dns.rcode.REFUSED]
            ) or (not response.answer)
            self.log_query("A", MALICIOUS_TEST_DOMAIN, "malicious", response, rtt)
            print(
                f"      result: blocks={blocks_malicious}, rcode={rcode_text}, "
                f"rtt_ms={rtt:.3f}"
            )
            return blocks_malicious, rcode_text, rtt
        except dns.exception.Timeout:
            self.log_query(
                "A",
                MALICIOUS_TEST_DOMAIN,
                "malicious",
                None,
                DNS_TIMEOUT * 1000,
            )
            print("      result: TIMEOUT")
            return False, "TIMEOUT", None
        except Exception:
            self.log_query("A", MALICIOUS_TEST_DOMAIN, "malicious", None, None)
            print("      result: ERROR (exception during malicious-domain check)")
            return False, "ERROR", None

    # ----------------------------------------------------------------------
    # Traceroute test (to resolver IP itself)
    # ----------------------------------------------------------------------

    def _run_traceroute_command(
        self,
        dest_ip: str,
    ) -> Tuple[bool, str, str, Optional[float]]:
        """
        Run OS traceroute/tracert to dest_ip.
        Returns (success, status_code, output_text, elapsed_ms).
        """
        system = platform.system()
        if system == "Windows":
            cmd = ["tracert", "-d", "-h", "30", "-w", "3000", dest_ip]
        else:
            # Linux / macOS: traceroute -n to avoid DNS lookups
            cmd = ["traceroute", "-n", "-m", "30", "-w", "3", dest_ip]

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            elapsed_ms = (time.time() - start) * 1000
            output = proc.stdout if proc.stdout else proc.stderr
            success = proc.returncode == 0
            status = "OK" if success else f"EXIT_{proc.returncode}"
            return success, status, output, elapsed_ms
        except FileNotFoundError:
            elapsed_ms = (time.time() - start) * 1000
            return False, "NO_TRACEROUTE", "traceroute/tracert command not found", elapsed_ms
        except subprocess.TimeoutExpired:
            elapsed_ms = (time.time() - start) * 1000
            return False, "TIMEOUT", "traceroute command timed out", elapsed_ms
        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            return False, "ERROR", f"Exception during traceroute: {e}", elapsed_ms

    def check_traceroute(self) -> Tuple[bool, str, Optional[float]]:
        """
        Traceroute directly from the local machine to this DNS server IP
        (self.server_ip), without involving a test domain.

        Logs one entry into dns_query_logs with test_type='traceroute'.
        """
        print(
            f"    [STEP] Traceroute test to resolver {self.server_ip} "
            f"(from local host)"
        )

        success, status, output, elapsed_ms = self._run_traceroute_command(self.server_ip)
        self.log_traceroute(self.server_ip, status, output, elapsed_ms)

        print(
            f"      result: success={success}, status={status}, "
            f"total_time_ms={elapsed_ms:.3f}"
        )
        return success, status, elapsed_ms

    # ----------------------------------------------------------------------
    # DNS cache TTL test (isc.org), only for local ISP/DHCP resolvers
    # ----------------------------------------------------------------------

    def check_cache_ttl(self) -> Tuple[Optional[int], str]:
        """
        Cache TTL / invalidation probe using CACHE_TTL_TEST_DOMAIN (isc.org).

        Runs only for private, ISP-assigned resolvers (e.g. 192.168.x.x).
        - First: 4 A queries with 1s delay between them.
        - If the last observed TTL <= 3, send 15 more probes with 1s delay.
        - Logs all into dns_query_logs with test_type='cache_ttl'.
        - Returns (ttl_last, rcode_last).
        """
        print(
            f"    [STEP] Cache TTL test for {self.server_ip} "
            f"(domain={CACHE_TTL_TEST_DOMAIN})"
        )

        last_ttl: Optional[int] = None
        last_rcode: str = "N/A"

        # First phase: 4 probes
        for i in range(1, 5):
            try:
                query, response, rtt = self._udp_query(
                    CACHE_TTL_TEST_DOMAIN,
                    dns.rdatatype.A,
                    set_rd=True,
                )
                rcode = dns.rcode.to_text(response.rcode())
                self.log_query(
                    "A",
                    CACHE_TTL_TEST_DOMAIN,
                    "cache_ttl",
                    response,
                    rtt,
                    "RD",
                )

                ttl = self._extract_ttl(response) if response else None
                last_ttl = ttl
                last_rcode = rcode

                rtt_str = f"{rtt:.3f}" if response else "N/A"

                print(
                    f"      probe {i}: rcode={rcode}, "
                    f"ttl={ttl if ttl is not None else 'N/A'}, "
                    f"rtt_ms={rtt_str}"
                )

            except dns.exception.Timeout:
                self.log_query(
                    "A",
                    CACHE_TTL_TEST_DOMAIN,
                    "cache_ttl",
                    None,
                    DNS_TIMEOUT * 1000,
                    "RD",
                )
                last_ttl = None
                last_rcode = "TIMEOUT"
                print(f"      probe {i}: TIMEOUT")
            except Exception as e:
                self.log_query(
                    "A",
                    CACHE_TTL_TEST_DOMAIN,
                    "cache_ttl",
                    None,
                    None,
                    "RD",
                )
                last_ttl = None
                last_rcode = "ERROR"
                print(f"      probe {i}: ERROR during cache TTL test: {e}")

            if i < 4:
                time.sleep(1)

        # Second phase: high-resolution probes when TTL is about to expire
        if last_ttl is not None and last_ttl <= 3 and last_rcode == "NOERROR":
            print(
                f"    [STEP] Cache TTL near expiry for {self.server_ip} "
                f"(ttl={last_ttl}) - sending 15 additional probes"
            )
            for j in range(1, 16):
                try:
                    query, response, rtt = self._udp_query(
                        CACHE_TTL_TEST_DOMAIN,
                        dns.rdatatype.A,
                        set_rd=True,
                    )
                    rcode = dns.rcode.to_text(response.rcode())
                    self.log_query(
                        "A",
                        CACHE_TTL_TEST_DOMAIN,
                        "cache_ttl",
                        response,
                        rtt,
                        "RD",
                    )

                    ttl = self._extract_ttl(response) if response else None
                    last_ttl = ttl
                    last_rcode = rcode

                    rtt_str = f"{rtt:.3f}" if response else "N/A"

                    print(
                        f"      fine-probe {j}: rcode={rcode}, "
                        f"ttl={ttl if ttl is not None else 'N/A'}, "
                        f"rtt_ms={rtt_str}"
                    )

                except dns.exception.Timeout:
                    self.log_query(
                        "A",
                        CACHE_TTL_TEST_DOMAIN,
                        "cache_ttl",
                        None,
                        DNS_TIMEOUT * 1000,
                        "RD",
                    )
                    last_ttl = None
                    last_rcode = "TIMEOUT"
                    print(f"      fine-probe {j}: TIMEOUT")
                except Exception as e:
                    self.log_query(
                        "A",
                        CACHE_TTL_TEST_DOMAIN,
                        "cache_ttl",
                        None,
                        None,
                        "RD",
                    )
                    last_ttl = None
                    last_rcode = "ERROR"
                    print(f"      fine-probe {j}: ERROR during cache TTL test: {e}")

                if j < 15:
                    time.sleep(1)

        print(
            "      summary: last_rcode="
            f"{last_rcode}, last_ttl={last_ttl if last_ttl is not None else 'N/A'}"
        )
        return last_ttl, last_rcode

    # ----------------------------------------------------------------------
    # Orchestrator
    # ----------------------------------------------------------------------

    def analyze(
        self,
        is_isp_assigned: bool = False,
        system_hostname: str = "unknown",
        public_ip: Optional[str] = None,
    ) -> ServerResult:
        """Run complete analysis on the DNS server with reliability tracking."""
        self.system_hostname = system_hostname
        print(f"  [SERVER] Starting analysis for {self.server_ip}")

        # 1) Recursion check
        is_recursive, ra_flag_set, _, recursion_rcode = self.check_recursion()

        # 2) Latency check (CRITICAL - determines server responsiveness)
        latency_ms, latency_rcode = self.check_latency()

        # Determine server responsiveness and test reliability
        server_responsive = latency_ms is not None and latency_rcode == "NOERROR"

        if server_responsive:
            test_reliability = "RELIABLE"
            failure_reason = None
        elif latency_rcode == "TIMEOUT":
            test_reliability = "UNRELIABLE_TIMEOUT"
            failure_reason = "Server timeout - not responding to queries"
            print("    [WARN] Server timeout - results considered unreliable")
        elif latency_rcode == "REFUSED":
            test_reliability = "UNRELIABLE_REFUSED"
            failure_reason = "Server refused queries - access denied or policy restriction"
            print("    [WARN] Server refused queries - results considered unreliable")
        elif latency_rcode == "SERVFAIL":
            test_reliability = "UNRELIABLE_SERVER_DOWN"
            failure_reason = "Server failure - internal server error"
            print("    [WARN] Server failure (SERVFAIL) - results considered unreliable")
        else:
            test_reliability = "UNRELIABLE_SERVER_DOWN"
            failure_reason = f"Server not responding properly - RCODE: {latency_rcode}"
            print("    [WARN] Server not responding properly - results considered unreliable")

        # 3) WHOIS (from cache only - no RDAP lookups here)
        organization, asn, asn_description, country = self.get_whois_info()

        # 4) DNSSEC (run but mark as unreliable if server is down)
        dnssec_enabled_raw, ad_flag_set, dnssec_rcode, _ = self.check_dnssec()

        # 5) Malicious blocking (run but interpret based on server health)
        malicious_blocking_raw, malicious_rcode, _ = self.check_malicious_blocking()

        # 6) Traceroute test (now to resolver IP)
        traceroute_success, traceroute_status, traceroute_time_ms = self.check_traceroute()

        # 7) Cache TTL test (isc.org), ONLY for local, ISP-assigned resolvers
        cache_ttl = None
        cache_ttl_rcode = None
        if is_isp_assigned and self._is_private_ip():
            cache_ttl, cache_ttl_rcode = self.check_cache_ttl()
        else:
            print("    [STEP] Cache TTL test skipped (not local ISP/DHCP resolver)")

        # Smart interpretation: If server is not responsive, set blocking/DNSSEC to None
        if not server_responsive:
            dnssec_enabled = None
            malicious_blocking = None
        else:
            dnssec_enabled = dnssec_enabled_raw
            if malicious_rcode in ["REFUSED", "SERVFAIL", "TIMEOUT"]:
                malicious_blocking = None  # Cannot determine reliably
            else:
                malicious_blocking = malicious_blocking_raw

        # Final per-server summary log
        summary_latency = round(latency_ms, 3) if latency_ms is not None else "N/A"
        cache_ttl_str = cache_ttl if cache_ttl is not None else "N/A"
        print(
            "  [SUMMARY] "
            f"server={self.server_ip}, "
            f"recursive={is_recursive}, "
            f"latency_ms={summary_latency}, "
            f"dnssec_enabled={dnssec_enabled}, "
            f"blocks_malicious={malicious_blocking}, "
            f"traceroute_status={traceroute_status}, "
            f"cache_ttl_isc_org={cache_ttl_str}, "
            f"whois_org={organization}, "
            f"country={country}, "
            f"reliability={test_reliability}"
        )

        result = ServerResult(
            server_ip=self.server_ip,
            system_hostname=system_hostname,
            public_ip=public_ip,
            timestamp=datetime.datetime.utcnow(),
            is_recursive=is_recursive,
            ra_flag_set=ra_flag_set,
            latency_ms=summary_latency if isinstance(summary_latency, float) else None,
            organization=organization,
            asn=asn,
            asn_description=asn_description,
            country=country,
            dnssec_enabled=dnssec_enabled,
            ad_flag_set=ad_flag_set,
            dnssec_rcode=dnssec_rcode,
            malicious_blocking=malicious_blocking,
            malicious_rcode=malicious_rcode,
            is_isp_assigned=is_isp_assigned,
            server_responsive=server_responsive,
            test_reliability=test_reliability,
            failure_reason=failure_reason,
            query_logs=self.query_logs,
        )
        return result
