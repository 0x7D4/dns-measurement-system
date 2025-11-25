# database.py

import psycopg2
from psycopg2.extras import execute_values
from typing import List, Optional, Tuple, Dict

from config import DB_CONFIG
from models import DNSQueryLog, ServerResult


class PostgreSQLDatabase:
    def __init__(self):
        self.conn = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            print(f"✅ Connected to PostgreSQL database: {DB_CONFIG['database']}")
        except psycopg2.Error as e:
            print(f"❌ Database connection failed: {e}")
            raise

    def create_tables(self):
        """Create tables if they don't exist (idempotent)"""
        commands = [
            """
            CREATE TABLE IF NOT EXISTS dns_query_logs (
                id SERIAL PRIMARY KEY,
                server_ip INET NOT NULL,
                query_type VARCHAR(10) NOT NULL,
                query_name VARCHAR(255) NOT NULL,
                query_flags TEXT,
                response_rcode VARCHAR(50) NOT NULL,
                response_flags TEXT,
                response_answer TEXT,
                response_ttl INTEGER,
                response_time_ms NUMERIC(10, 3),
                timestamp TIMESTAMPTZ NOT NULL,
                test_type VARCHAR(50) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(server_ip, query_type, query_name, test_type, timestamp)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_dns_logs_server_ip
                ON dns_query_logs(server_ip);
            CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp
                ON dns_query_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_logs_test_type
                ON dns_query_logs(test_type);
            CREATE INDEX IF NOT EXISTS idx_dns_logs_ttl
                ON dns_query_logs(response_ttl);
            """,
            """
            CREATE TABLE IF NOT EXISTS whois_cache (
                id SERIAL PRIMARY KEY,
                server_ip INET NOT NULL UNIQUE,
                organization VARCHAR(255),
                asn VARCHAR(20),
                asn_description TEXT,
                country VARCHAR(10),
                last_updated TIMESTAMPTZ DEFAULT NOW(),
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_whois_cache_server_ip
                ON whois_cache(server_ip);
            CREATE INDEX IF NOT EXISTS idx_whois_cache_last_updated
                ON whois_cache(last_updated);
            """,
            """
            CREATE TABLE IF NOT EXISTS server_analysis_results (
                id SERIAL PRIMARY KEY,
                server_ip INET NOT NULL,
                system_hostname VARCHAR(255),
                public_ip INET,
                timestamp TIMESTAMPTZ NOT NULL,
                is_recursive BOOLEAN NOT NULL,
                ra_flag_set BOOLEAN NOT NULL,
                latency_ms NUMERIC(10, 3),
                organization VARCHAR(255),
                asn VARCHAR(20),
                asn_description TEXT,
                country VARCHAR(10),
                dnssec_enabled BOOLEAN,
                ad_flag_set BOOLEAN,
                dnssec_rcode VARCHAR(50),
                malicious_blocking BOOLEAN,
                malicious_rcode VARCHAR(50),
                is_isp_assigned BOOLEAN DEFAULT FALSE,
                server_responsive BOOLEAN DEFAULT TRUE,
                test_reliability VARCHAR(50) DEFAULT 'RELIABLE',
                failure_reason TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(server_ip, timestamp)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_server_results_server_ip
                ON server_analysis_results(server_ip);
            CREATE INDEX IF NOT EXISTS idx_server_results_timestamp
                ON server_analysis_results(timestamp);
            CREATE INDEX IF NOT EXISTS idx_server_results_recursive
                ON server_analysis_results(is_recursive);
            CREATE INDEX IF NOT EXISTS idx_server_results_system_hostname
                ON server_analysis_results(system_hostname);
            CREATE INDEX IF NOT EXISTS idx_server_results_public_ip
                ON server_analysis_results(public_ip);
            CREATE INDEX IF NOT EXISTS idx_server_results_is_isp_assigned
                ON server_analysis_results(is_isp_assigned);
            CREATE INDEX IF NOT EXISTS idx_server_results_test_reliability
                ON server_analysis_results(test_reliability);
            CREATE INDEX IF NOT EXISTS idx_server_results_server_responsive
                ON server_analysis_results(server_responsive);
            """,
            # NEW: table to store measurement host identity (hostname, public IP, ASN, org, etc.)
            """
            CREATE TABLE IF NOT EXISTS measurement_hosts (
                id SERIAL PRIMARY KEY,
                system_hostname VARCHAR(255) NOT NULL,
                public_ip INET NOT NULL,
                organization VARCHAR(255),
                asn VARCHAR(20),
                asn_description TEXT,
                country VARCHAR(10),
                first_seen TIMESTAMPTZ DEFAULT NOW(),
                last_seen TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(system_hostname, public_ip)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_hosts_hostname
                ON measurement_hosts(system_hostname);
            CREATE INDEX IF NOT EXISTS idx_hosts_public_ip
                ON measurement_hosts(public_ip);
            """,
        ]

        try:
            with self.conn.cursor() as cur:
                for command in commands:
                    cur.execute(command)
            self.conn.commit()
            print("✅ Database tables created/verified successfully")
        except psycopg2.Error as e:
            print(f"❌ Failed to create tables: {e}")
            self.conn.rollback()
            raise

    def get_whois_cache(self, server_ip: str) -> Optional[Tuple[str, str, str, str]]:
        """Get cached WHOIS data for an IP"""
        query = """
        SELECT organization, asn, asn_description, country
        FROM whois_cache
        WHERE server_ip = %s
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (server_ip,))
                result = cur.fetchone()
                if result:
                    return result
                return None
        except psycopg2.Error:
            return None

    def save_whois_cache(
        self,
        server_ip: str,
        organization: str,
        asn: str,
        asn_description: str,
        country: str,
    ):
        """Save WHOIS data to cache"""
        query = """
        INSERT INTO whois_cache (server_ip, organization, asn, asn_description, country)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (server_ip)
        DO UPDATE SET
            organization   = EXCLUDED.organization,
            asn            = EXCLUDED.asn,
            asn_description= EXCLUDED.asn_description,
            country        = EXCLUDED.country,
            last_updated   = NOW()
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    query,
                    (server_ip, organization, asn, asn_description, country),
                )
            self.conn.commit()
        except psycopg2.Error as e:
            print(f"❌ Failed to save WHOIS cache: {e}")
            self.conn.rollback()

    def get_ips_without_whois(self, limit: int = 50) -> List[str]:
        """Get IPs that don't have WHOIS data yet (for batch enrichment)"""
        query = """
        SELECT DISTINCT server_ip
        FROM server_analysis_results
        WHERE server_ip NOT IN (SELECT server_ip FROM whois_cache)
        LIMIT %s
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (limit,))
                return [str(row[0]) for row in cur.fetchall()]
        except psycopg2.Error:
            return []

    def get_whois_stats(self) -> Dict[str, int]:
        """Get WHOIS cache statistics"""
        try:
            with self.conn.cursor() as cur:
                # Total unique IPs in analysis results
                cur.execute("SELECT COUNT(DISTINCT server_ip) FROM server_analysis_results")
                total_ips = cur.fetchone()[0]

                # IPs with WHOIS data
                cur.execute("SELECT COUNT(*) FROM whois_cache")
                cached_ips = cur.fetchone()[0]

            return {
                "total_ips": total_ips,
                "cached_ips": cached_ips,
                "missing_ips": total_ips - cached_ips,
            }
        except psycopg2.Error:
            return {"total_ips": 0, "cached_ips": 0, "missing_ips": 0}

    # NEW: upsert local measurement host identity
    def upsert_measurement_host(
        self,
        system_hostname: str,
        public_ip: str,
        organization: str,
        asn: str,
        asn_description: str,
        country: str,
    ) -> None:
        """
        Insert or update the local measurement host record.

        Keyed by (system_hostname, public_ip) so the same host reuses a row
        and only refreshes WHOIS/AS data and last_seen.
        """
        query = """
        INSERT INTO measurement_hosts (
            system_hostname,
            public_ip,
            organization,
            asn,
            asn_description,
            country
        ) VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (system_hostname, public_ip)
        DO UPDATE SET
            organization    = EXCLUDED.organization,
            asn             = EXCLUDED.asn,
            asn_description = EXCLUDED.asn_description,
            country         = EXCLUDED.country,
            last_seen       = NOW()
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        system_hostname,
                        public_ip,
                        organization,
                        asn,
                        asn_description,
                        country,
                    ),
                )
            self.conn.commit()
            print(
                f"💻 Recorded host identity: {system_hostname} / {public_ip} "
                f"(ASN {asn}, org={organization})"
            )
        except psycopg2.Error as e:
            print(f"❌ Failed to upsert measurement host: {e}")
            self.conn.rollback()

    def log_queries(self, query_logs: List[DNSQueryLog]):
        """Log DNS queries to database in batch"""
        if not query_logs:
            return

        query = """
        INSERT INTO dns_query_logs (
            server_ip,
            query_type,
            query_name,
            query_flags,
            response_rcode,
            response_flags,
            response_answer,
            response_ttl,
            response_time_ms,
            timestamp,
            test_type
        ) VALUES %s
        ON CONFLICT (server_ip, query_type, query_name, test_type, timestamp)
        DO NOTHING
        """

        values = [
            (
                log.server_ip,
                log.query_type,
                log.query_name,
                log.query_flags,
                log.response_rcode,
                log.response_flags,
                log.response_answer,
                log.response_ttl,
                log.response_time_ms,
                log.timestamp,
                log.test_type,
            )
            for log in query_logs
        ]

        try:
            with self.conn.cursor() as cur:
                execute_values(cur, query, values)
            self.conn.commit()
            print(f" 📊 Logged {len(query_logs)} DNS queries to database")
        except psycopg2.Error as e:
            print(f"❌ Failed to log queries: {e}")
            self.conn.rollback()
            raise

    def save_server_result(self, result: ServerResult):
        """Save server analysis result (allows multiple entries per IP for time-series data)"""
        query = """
        INSERT INTO server_analysis_results (
            server_ip,
            system_hostname,
            public_ip,
            timestamp,
            is_recursive,
            ra_flag_set,
            latency_ms,
            organization,
            asn,
            asn_description,
            country,
            dnssec_enabled,
            ad_flag_set,
            dnssec_rcode,
            malicious_blocking,
            malicious_rcode,
            is_isp_assigned,
            server_responsive,
            test_reliability,
            failure_reason
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (server_ip, timestamp)
        DO UPDATE SET
            system_hostname   = EXCLUDED.system_hostname,
            public_ip         = EXCLUDED.public_ip,
            is_recursive      = EXCLUDED.is_recursive,
            ra_flag_set       = EXCLUDED.ra_flag_set,
            latency_ms        = EXCLUDED.latency_ms,
            organization      = EXCLUDED.organization,
            asn               = EXCLUDED.asn,
            asn_description   = EXCLUDED.asn_description,
            country           = EXCLUDED.country,
            dnssec_enabled    = EXCLUDED.dnssec_enabled,
            ad_flag_set       = EXCLUDED.ad_flag_set,
            dnssec_rcode      = EXCLUDED.dnssec_rcode,
            malicious_blocking= EXCLUDED.malicious_blocking,
            malicious_rcode   = EXCLUDED.malicious_rcode,
            is_isp_assigned   = EXCLUDED.is_isp_assigned,
            server_responsive = EXCLUDED.server_responsive,
            test_reliability  = EXCLUDED.test_reliability,
            failure_reason    = EXCLUDED.failure_reason,
            updated_at        = NOW()
        """

        values = (
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
            result.failure_reason,
        )

        try:
            with self.conn.cursor() as cur:
                cur.execute(query, values)
            self.conn.commit()
            print(f" 💾 Saved server result in database")
        except psycopg2.Error as e:
            print(f"❌ Failed to save server result: {e}")
            self.conn.rollback()
            raise

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✅ Database connection closed")

    def reconnect(self):
        """Reconnect to database if connection is lost"""
        try:
            if self.conn:
                self.conn.close()
            self.connect()
        except Exception as e:
            print(f"❌ Reconnection failed: {e}")
            raise
