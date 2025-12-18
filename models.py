from dataclasses import dataclass, field
from typing import List, Optional
import datetime


@dataclass
class DNSQueryLog:
    """
    Represents a single DNS query and its response.
    Logged for detailed analysis and debugging.
    All timestamps are in UTC.
    """
    server_ip: str
    system_hostname: str
    query_type: str  # A, AAAA, CNAME, etc.
    query_name: str  # Domain queried
    query_flags: str  # RD, AD, CD, DO, etc.
    response_rcode: str  # NOERROR, NXDOMAIN, SERVFAIL, etc.
    response_flags: str  # QR, AA, TC, RD, RA, AD, CD
    response_answer: Optional[str]  # Answer section (RRsets)
    response_ttl: Optional[int]  # TTL from answer
    response_time_ms: Optional[float]  # Query latency
    timestamp: datetime.datetime  # UTC timestamp
    test_type: str  # recursion, latency, dnssec, malicious, cache_ttl, traceroute


@dataclass
class ServerResult:
    """
    Aggregated analysis result for a single DNS server.
    Stored in server_analysis_results table.
    All timestamps are in UTC.
    """
    server_ip: str
    system_hostname: str
    public_ip: Optional[str]
    timestamp: datetime.datetime  # UTC timestamp
    
    # Recursion
    is_recursive: bool
    ra_flag_set: bool
    
    # Performance
    latency_ms: Optional[float]
    
    # WHOIS/Geolocation
    organization: str
    asn: str
    asn_description: str
    country: str
    
    # DNSSEC
    dnssec_enabled: Optional[bool]
    ad_flag_set: bool
    dnssec_rcode: str
    
    # Malicious blocking
    malicious_blocking: Optional[bool]
    malicious_rcode: str
    
    # Metadata with defaults
    # RFC 8027 Section 3.1.12 - Permissive DNSSEC check
    # True = resolver correctly rejects broken DNSSEC with SERVFAIL (strict/good)
    # False = resolver permissively accepts broken DNSSEC (bad)
    # None = could not determine (server unresponsive)
    dnssec_strict: Optional[bool] = None
    dnssec_strict_rcode: Optional[str] = None
    is_isp_assigned: bool = False
    server_responsive: bool = True
    test_reliability: str = "RELIABLE"
    failure_reason: Optional[str] = None
    
    # Associated query logs
    query_logs: List[DNSQueryLog] = field(default_factory=list)


@dataclass
class MeasurementHost:
    """
    Represents a measurement anchor (device running the analysis).
    Stored in measurement_hosts table.
    All timestamps are in UTC.
    """
    system_hostname: str
    public_ip: Optional[str]
    organization: Optional[str]
    asn: Optional[str]
    asn_description: Optional[str]
    country: Optional[str]
    supports_dns: bool = False
    supports_recursion: bool = False
    dns_latency_ms: Optional[float] = None
    first_seen: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    last_seen: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
