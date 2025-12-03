#!/usr/bin/env python3
"""
Database migration: Convert all timestamp columns to UTC-aware TIMESTAMPTZ
"""

from database import PostgreSQLDatabase

def run_migration():
    db = None
    try:
        print("=" * 80)
        print("Database Migration: Converting Timestamps to UTC (TIMESTAMPTZ)")
        print("=" * 80)
        
        db = PostgreSQLDatabase()
        
        print("\n1. Converting server_analysis_results.timestamp...")
        db.cursor.execute("""
            ALTER TABLE server_analysis_results 
            ALTER COLUMN timestamp TYPE TIMESTAMP WITH TIME ZONE 
            USING timestamp AT TIME ZONE 'UTC';
        """)
        print("   ✓ Done")
        
        print("\n2. Converting dns_query_logs.timestamp...")
        db.cursor.execute("""
            ALTER TABLE dns_query_logs 
            ALTER COLUMN timestamp TYPE TIMESTAMP WITH TIME ZONE 
            USING timestamp AT TIME ZONE 'UTC';
        """)
        print("   ✓ Done")
        
        print("\n3. Converting whois_cache.last_updated...")
        db.cursor.execute("""
            ALTER TABLE whois_cache 
            ALTER COLUMN last_updated TYPE TIMESTAMP WITH TIME ZONE 
            USING last_updated AT TIME ZONE 'UTC';
        """)
        print("   ✓ Done")
        
        print("\n4. Converting measurement_hosts.first_seen...")
        db.cursor.execute("""
            ALTER TABLE measurement_hosts 
            ALTER COLUMN first_seen TYPE TIMESTAMP WITH TIME ZONE 
            USING first_seen AT TIME ZONE 'UTC';
        """)
        print("   ✓ Done")
        
        print("\n5. Converting measurement_hosts.last_seen...")
        db.cursor.execute("""
            ALTER TABLE measurement_hosts 
            ALTER COLUMN last_seen TYPE TIMESTAMP WITH TIME ZONE 
            USING last_seen AT TIME ZONE 'UTC';
        """)
        print("   ✓ Done")
        
        db.conn.commit()
        
        print("\n" + "=" * 80)
        print("✅ Migration completed successfully!")
        print("All timestamps are now stored as UTC with timezone awareness")
        print("=" * 80)
        
        # Verify schema
        print("\nVerifying schema...")
        db.cursor.execute("""
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_name IN ('server_analysis_results', 'dns_query_logs', 
                                 'whois_cache', 'measurement_hosts')
              AND column_name IN ('timestamp', 'last_updated', 'first_seen', 'last_seen')
            ORDER BY table_name, column_name;
        """)
        
        print("\nTimestamp columns:")
        print("-" * 80)
        for row in db.cursor.fetchall():
            print(f"  {row[0]:30s} {row[1]:20s} {row[2]}")
        print("-" * 80)
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if db:
            db.close()

if __name__ == "__main__":
    run_migration()
