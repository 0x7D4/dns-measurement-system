# models.py

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class DNSQueryLog:
    """Model for logging DNS queries to PostgreSQL"""
    server_ip: str
    system_hostname: str
    query_type: str
    query_name: str
    query_flags: str
    response_rcode: str
    response_flags: str
    response_answer: Optional[str]
    response_ttl: Optional[int]
    response_time_ms: Optional[float]
    timestamp: datetime
    test_type: str


@dataclass
class ServerResult:
    """Complete analysis result for a DNS server"""
    server_ip: str
    system_hostname: str
    public_ip: Optional[str]
    timestamp: datetime

    is_recursive: bool
    ra_flag_set: bool
    latency_ms: Optional[float]

    organization: str
    asn: str
    asn_description: str
    country: str

    dnssec_enabled: Optional[bool]
    ad_flag_set: bool
    dnssec_rcode: str

    malicious_blocking: Optional[bool]
    malicious_rcode: str

    is_isp_assigned: bool
    server_responsive: bool
    test_reliability: str
    failure_reason: Optional[str]

    query_logs: List[DNSQueryLog]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_ip": self.server_ip,
            "system_hostname": self.system_hostname,
            "public_ip": self.public_ip,
            "timestamp": self.timestamp.isoformat(),
            "is_recursive": self.is_recursive,
            "ra_flag_set": self.ra_flag_set,
            "latency_ms": self.latency_ms,
            "organization": self.organization,
            "asn": self.asn,
            "asn_description": self.asn_description,
            "country": self.country,
            "dnssec_enabled": self.dnssec_enabled,
            "ad_flag_set": self.ad_flag_set,
            "dnssec_rcode": self.dnssec_rcode,
            "malicious_blocking": self.malicious_blocking,
            "malicious_rcode": self.malicious_rcode,
            "is_isp_assigned": self.is_isp_assigned,
            "server_responsive": self.server_responsive,
            "test_reliability": self.test_reliability,
            "failure_reason": self.failure_reason,
            "query_logs": [log.__dict__ for log in self.query_logs],
        }
