# config.py

import os

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "database": os.getenv("DB_NAME", "dns_analyzer"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}

DNS_TIMEOUT = 5

# Test domains
RECURSION_TEST_DOMAIN = "google.com"
LATENCY_TEST_DOMAIN = "google.com"
DNSSEC_TEST_DOMAIN = "iifon.org"
MALICIOUS_TEST_DOMAIN = "008k.com"
TRACEROUTE_TEST_DOMAIN = "ietf.org"     # used by traceroute test
CACHE_TTL_TEST_DOMAIN = "isc.org"       # used by DNS cache TTL/invalidation test

# Input and scheduling
INPUT_FILE = "test.json"
LOOP_INTERVAL = 3600  # 1 hour
DEFAULT_DELAY = 0.1
DEFAULT_BATCH_SIZE = 100
