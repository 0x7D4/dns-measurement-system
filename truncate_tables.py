#!/usr/bin/env python3
"""
Truncate all tables in the DNS Analyzer database.
Clears all data while preserving table structure.
"""

import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'dns_analyzer'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

try:
    print("=" * 80)
    print("Truncating DNS Analyzer Database Tables")
    print("=" * 80)
    
    conn = psycopg2.connect(**db_config)
    conn.autocommit = True
    
    with conn.cursor() as cur:
        # Truncate all 4 tables
        print("\n[1/4] Truncating dns_query_logs...")
        cur.execute("TRUNCATE TABLE dns_query_logs RESTART IDENTITY CASCADE;")
        print("      Done")
        
        print("\n[2/4] Truncating server_analysis_results...")
        cur.execute("TRUNCATE TABLE server_analysis_results RESTART IDENTITY CASCADE;")
        print("      Done")
        
        print("\n[3/4] Truncating whois_cache...")
        cur.execute("TRUNCATE TABLE whois_cache RESTART IDENTITY CASCADE;")
        print("      Done")
        
        print("\n[4/4] Truncating measurement_hosts...")
        cur.execute("TRUNCATE TABLE measurement_hosts RESTART IDENTITY CASCADE;")
        print("      Done")
        
        print("\n" + "=" * 80)
        print("All tables truncated successfully!")
        print("=" * 80)
        
        # Verify all tables are empty
        print("\nVerifying table counts:")
        print("-" * 80)
        
        cur.execute("SELECT count(*) FROM dns_query_logs;")
        query_count = cur.fetchone()[0]
        print(f"  dns_query_logs:           {query_count:>10} rows")
        
        cur.execute("SELECT count(*) FROM server_analysis_results;")
        result_count = cur.fetchone()[0]
        print(f"  server_analysis_results:  {result_count:>10} rows")
        
        cur.execute("SELECT count(*) FROM whois_cache;")
        whois_count = cur.fetchone()[0]
        print(f"  whois_cache:              {whois_count:>10} rows")
        
        cur.execute("SELECT count(*) FROM measurement_hosts;")
        hosts_count = cur.fetchone()[0]
        print(f"  measurement_hosts:        {hosts_count:>10} rows")
        
        print("-" * 80)
        print(f"  Total:                    {query_count + result_count + whois_count + hosts_count:>10} rows")
        print("=" * 80)
    
    conn.close()
    
except psycopg2.Error as e:
    print(f"\nDatabase Error: {e}")
    print("Make sure:")
    print("  1. PostgreSQL is running")
    print("  2. Database credentials in .env are correct")
    print("  3. Tables exist in the database")
except Exception as e:
    print(f"\nError: {e}")
