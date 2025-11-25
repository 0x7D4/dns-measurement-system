#!/usr/bin/env python3
# truncate_tables.py
import psycopg2
import os

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'dns_analyzer'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

try:
    conn = psycopg2.connect(**db_config)
    conn.autocommit = True
    
    with conn.cursor() as cur:
        print("Truncating dns_query_logs...")
        cur.execute("TRUNCATE TABLE dns_query_logs RESTART IDENTITY CASCADE;")
        
        print("Truncating server_analysis_results...")
        cur.execute("TRUNCATE TABLE server_analysis_results RESTART IDENTITY CASCADE;")
        
        print("✅ Tables truncated successfully!")
        
        # Verify
        cur.execute("SELECT count(*) FROM dns_query_logs;")
        query_count = cur.fetchone()[0]
        
        cur.execute("SELECT count(*) FROM server_analysis_results;")
        result_count = cur.fetchone()[0]
        
        print(f"dns_query_logs: {query_count} rows")
        print(f"server_analysis_results: {result_count} rows")
    
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
