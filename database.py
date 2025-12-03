import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Optional, Tuple
import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "database": os.getenv("DB_NAME", "dns_analyzer"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}


class PostgreSQLDatabase:
    def __init__(self):
        """Initialize database connection and create tables if needed."""
        self.conn = psycopg2.connect(**DB_CONFIG)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        """Create all necessary database tables if they don't exist."""
        
        # Table 1: Server analysis results (aggregated per server per run)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS server_analysis_results (
                id SERIAL PRIMARY KEY,
                server_ip TEXT NOT NULL,
                system_hostname TEXT,
                public_ip TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_recursive BOOLEAN,
                ra_flag_set BOOLEAN,
                latency_ms FLOAT,
                organization TEXT,
                asn TEXT,
                asn_description TEXT,
                country TEXT,
                dnssec_enabled BOOLEAN,
                ad_flag_set BOOLEAN,
                dnssec_rcode TEXT,
                malicious_blocking BOOLEAN,
                malicious_rcode TEXT,
                is_isp_assigned BOOLEAN DEFAULT FALSE,
                server_responsive BOOLEAN DEFAULT TRUE,
                test_reliability TEXT DEFAULT 'RELIABLE',
                failure_reason TEXT
            );
        """)

        # Table 2: DNS query logs (detailed per-query logs)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_query_logs (
                id SERIAL PRIMARY KEY,
                server_ip TEXT NOT NULL,
                system_hostname TEXT,
                query_type TEXT,
                query_name TEXT,
                query_flags TEXT,
                response_rcode TEXT,
                response_flags TEXT,
                response_answer TEXT,
                response_ttl INTEGER,
                response_time_ms FLOAT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                test_type TEXT
            );
        """)

        # Table 3: WHOIS cache
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS whois_cache (
                server_ip TEXT PRIMARY KEY,
                organization TEXT,
                asn TEXT,
                asn_description TEXT,
                country TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Table 4: Measurement hosts (anchor tracking with DNS capability)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS measurement_hosts (
                system_hostname TEXT NOT NULL,
                public_ip TEXT,
                organization TEXT,
                asn TEXT,
                asn_description TEXT,
                country TEXT,
                supports_dns BOOLEAN DEFAULT FALSE,
                supports_recursion BOOLEAN DEFAULT FALSE,
                dns_latency_ms FLOAT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (system_hostname, public_ip)
            );
        """)

        # Create indexes for better query performance
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_server_ip ON server_analysis_results(server_ip);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON server_analysis_results(timestamp);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_system_hostname ON server_analysis_results(system_hostname);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_is_recursive ON server_analysis_results(is_recursive);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_query_server_ip ON dns_query_logs(server_ip);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_query_timestamp ON dns_query_logs(timestamp);
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_query_test_type ON dns_query_logs(test_type);
        """)

        self.conn.commit()

    def save_server_result(self, result):
        """
        Save aggregated server analysis result.
        Args:
            result: ServerResult object from models.py
        """
        query = """
        INSERT INTO server_analysis_results (
            server_ip, system_hostname, public_ip, timestamp,
            is_recursive, ra_flag_set, latency_ms,
            organization, asn, asn_description, country,
            dnssec_enabled, ad_flag_set, dnssec_rcode,
            malicious_blocking, malicious_rcode,
            is_isp_assigned, server_responsive, test_reliability, failure_reason
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(query, (
            result.server_ip,
            result.system_hostname,
            result.public_ip,
            result.timestamp,
            result.is_recursive,
            result.ra_flag_set,
            result.latency_ms,
            result.organization,
            result.asn,
            result.asn_description,
            result.country,
            result.dnssec_enabled,
            result.ad_flag_set,
            result.dnssec_rcode,
            result.malicious_blocking,
            result.malicious_rcode,
            result.is_isp_assigned,
            result.server_responsive,
            result.test_reliability,
            result.failure_reason
        ))
        self.conn.commit()

    def log_queries(self, query_logs: List):
        """
        Bulk insert DNS query logs.
        Args:
            query_logs: List of DNSQueryLog objects from models.py
        """
        if not query_logs:
            return

        query = """
        INSERT INTO dns_query_logs (
            server_ip, system_hostname, query_type, query_name, query_flags,
            response_rcode, response_flags, response_answer, response_ttl,
            response_time_ms, timestamp, test_type
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        data = [
            (
                log.server_ip,
                log.system_hostname,
                log.query_type,
                log.query_name,
                log.query_flags,
                log.response_rcode,
                log.response_flags,
                log.response_answer,
                log.response_ttl,
                log.response_time_ms,
                log.timestamp,
                log.test_type
            )
            for log in query_logs
        ]
        
        self.cursor.executemany(query, data)
        self.conn.commit()

    def get_whois_cache(self, server_ip: str) -> Optional[Tuple[str, str, str, str]]:
        """
        Retrieve WHOIS data from cache.
        Returns:
            Tuple of (organization, asn, asn_description, country) or None
        """
        query = """
        SELECT organization, asn, asn_description, country
        FROM whois_cache
        WHERE server_ip = %s
        """
        self.cursor.execute(query, (server_ip,))
        result = self.cursor.fetchone()
        return result if result else None

    def save_whois_cache(
        self,
        server_ip: str,
        organization: str,
        asn: str,
        asn_description: str,
        country: str
    ):
        """
        Save or update WHOIS data in cache.
        """
        query = """
        INSERT INTO whois_cache (server_ip, organization, asn, asn_description, country, last_updated)
        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (server_ip)
        DO UPDATE SET
            organization = EXCLUDED.organization,
            asn = EXCLUDED.asn,
            asn_description = EXCLUDED.asn_description,
            country = EXCLUDED.country,
            last_updated = CURRENT_TIMESTAMP
        """
        self.cursor.execute(query, (server_ip, organization, asn, asn_description, country))
        self.conn.commit()

    def get_whois_stats(self) -> dict:
        """
        Get WHOIS cache statistics based on server_analysis_results.
        Returns dict with total_ips, cached_ips, missing_ips
        """
        # Get total unique IPs from analysis results
        self.cursor.execute("""
            SELECT COUNT(DISTINCT server_ip) as total
            FROM server_analysis_results
        """)
        total_ips = self.cursor.fetchone()[0] or 0

        # Get cached IPs
        self.cursor.execute("""
            SELECT COUNT(DISTINCT server_ip) as cached
            FROM whois_cache
            WHERE server_ip IN (SELECT DISTINCT server_ip FROM server_analysis_results)
        """)
        cached_ips = self.cursor.fetchone()[0] or 0

        missing_ips = total_ips - cached_ips

        return {
            "total_ips": total_ips,
            "cached_ips": cached_ips,
            "missing_ips": missing_ips
        }

    def upsert_measurement_host(
        self,
        system_hostname: str,
        public_ip: str,
        organization: str,
        asn: str,
        asn_description: str,
        country: str,
        supports_dns: bool = False,
        supports_recursion: bool = False,
        dns_latency_ms: float = None
    ):
        """
        Insert or update measurement host information.
        Records anchor identity and DNS capability.
        """
        query = """
        INSERT INTO measurement_hosts (
            system_hostname, public_ip, organization, asn, asn_description, country,
            supports_dns, supports_recursion, dns_latency_ms, first_seen, last_seen
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT (system_hostname, public_ip)
        DO UPDATE SET
            organization = EXCLUDED.organization,
            asn = EXCLUDED.asn,
            asn_description = EXCLUDED.asn_description,
            country = EXCLUDED.country,
            supports_dns = EXCLUDED.supports_dns,
            supports_recursion = EXCLUDED.supports_recursion,
            dns_latency_ms = EXCLUDED.dns_latency_ms,
            last_seen = CURRENT_TIMESTAMP;
        """
        self.cursor.execute(query, (
            system_hostname, public_ip, organization, asn, asn_description, country,
            supports_dns, supports_recursion, dns_latency_ms
        ))
        self.conn.commit()

    def get_all_servers(self) -> List[str]:
        """
        Get list of all unique server IPs that have been analyzed.
        Returns:
            List of IP addresses
        """
        query = """
        SELECT DISTINCT server_ip
        FROM server_analysis_results
        ORDER BY server_ip
        """
        self.cursor.execute(query)
        return [row[0] for row in self.cursor.fetchall()]

    def get_server_history(self, server_ip: str, limit: int = 100) -> List[dict]:
        """
        Get historical analysis results for a specific server.
        Args:
            server_ip: IP address to query
            limit: Maximum number of results (default: 100)
        Returns:
            List of dicts containing analysis results
        """
        query = """
        SELECT 
            timestamp, is_recursive, latency_ms, dnssec_enabled, 
            malicious_blocking, organization, country, test_reliability
        FROM server_analysis_results
        WHERE server_ip = %s
        ORDER BY timestamp DESC
        LIMIT %s
        """
        self.cursor.execute(query, (server_ip, limit))
        
        columns = [desc[0] for desc in self.cursor.description]
        results = []
        for row in self.cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        return results

    def get_latest_analysis(self, server_ip: str) -> Optional[dict]:
        """
        Get the most recent analysis result for a server.
        Args:
            server_ip: IP address to query
        Returns:
            Dict containing latest analysis or None
        """
        query = """
        SELECT *
        FROM server_analysis_results
        WHERE server_ip = %s
        ORDER BY timestamp DESC
        LIMIT 1
        """
        self.cursor.execute(query, (server_ip,))
        
        row = self.cursor.fetchone()
        if row:
            columns = [desc[0] for desc in self.cursor.description]
            return dict(zip(columns, row))
        return None

    def get_query_logs(self, server_ip: str, test_type: Optional[str] = None, limit: int = 100) -> List[dict]:
        """
        Get DNS query logs for a specific server.
        Args:
            server_ip: IP address to query
            test_type: Optional filter by test type (recursion, latency, dnssec, etc.)
            limit: Maximum number of results (default: 100)
        Returns:
            List of dicts containing query logs
        """
        if test_type:
            query = """
            SELECT *
            FROM dns_query_logs
            WHERE server_ip = %s AND test_type = %s
            ORDER BY timestamp DESC
            LIMIT %s
            """
            self.cursor.execute(query, (server_ip, test_type, limit))
        else:
            query = """
            SELECT *
            FROM dns_query_logs
            WHERE server_ip = %s
            ORDER BY timestamp DESC
            LIMIT %s
            """
            self.cursor.execute(query, (server_ip, limit))
        
        columns = [desc[0] for desc in self.cursor.description]
        results = []
        for row in self.cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        return results

    def get_statistics(self) -> dict:
        """
        Get overall database statistics.
        Returns:
            Dict with various statistics
        """
        stats = {}
        
        # Total servers analyzed
        self.cursor.execute("SELECT COUNT(DISTINCT server_ip) FROM server_analysis_results")
        stats['total_servers'] = self.cursor.fetchone()[0] or 0
        
        # Total measurements
        self.cursor.execute("SELECT COUNT(*) FROM server_analysis_results")
        stats['total_measurements'] = self.cursor.fetchone()[0] or 0
        
        # Recursive servers
        self.cursor.execute("""
            SELECT COUNT(DISTINCT server_ip) 
            FROM server_analysis_results 
            WHERE is_recursive = TRUE
        """)
        stats['recursive_servers'] = self.cursor.fetchone()[0] or 0
        
        # DNSSEC-enabled servers
        self.cursor.execute("""
            SELECT COUNT(DISTINCT server_ip) 
            FROM server_analysis_results 
            WHERE dnssec_enabled = TRUE
        """)
        stats['dnssec_servers'] = self.cursor.fetchone()[0] or 0
        
        # Servers with malicious blocking
        self.cursor.execute("""
            SELECT COUNT(DISTINCT server_ip) 
            FROM server_analysis_results 
            WHERE malicious_blocking = TRUE
        """)
        stats['blocking_servers'] = self.cursor.fetchone()[0] or 0
        
        # Average latency
        self.cursor.execute("""
            SELECT AVG(latency_ms) 
            FROM server_analysis_results 
            WHERE latency_ms IS NOT NULL
        """)
        avg_latency = self.cursor.fetchone()[0]
        stats['avg_latency_ms'] = round(float(avg_latency), 2) if avg_latency else None
        
        # Total query logs
        self.cursor.execute("SELECT COUNT(*) FROM dns_query_logs")
        stats['total_query_logs'] = self.cursor.fetchone()[0] or 0
        
        # Measurement hosts
        self.cursor.execute("SELECT COUNT(*) FROM measurement_hosts")
        stats['measurement_hosts'] = self.cursor.fetchone()[0] or 0
        
        # Measurement hosts with DNS capability
        self.cursor.execute("SELECT COUNT(*) FROM measurement_hosts WHERE supports_dns = TRUE")
        stats['dns_capable_hosts'] = self.cursor.fetchone()[0] or 0
        
        return stats

    def truncate_all_tables(self):
        """
        Truncate all tables (for testing/cleanup).
        WARNING: This deletes all data!
        """
        tables = [
            'dns_query_logs',
            'server_analysis_results',
            'whois_cache',
            'measurement_hosts'
        ]
        
        for table in tables:
            self.cursor.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE")
        
        self.conn.commit()
        print("✓ All tables truncated")

    def close(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
