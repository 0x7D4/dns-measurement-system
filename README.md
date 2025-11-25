# DNS Server Analyzer

DNS Server Analyzer is a Python tool that measures the behavior and security posture of many DNS resolvers in bulk, storing detailed results in PostgreSQL for later analysis.  
It runs a set of DNS tests (recursion, latency, DNSSEC, malicious‑domain blocking) against each server and can enrich them with WHOIS data using a cache.  

---

## Features

- Recursion check to determine whether a resolver acts as a recursive/open resolver, using a configurable test domain.  
- Latency measurement to a configurable latency test domain, used to classify server responsiveness and reliability.  
- DNSSEC validation check using the AD flag for a configurable DNSSEC test domain.  
- Malicious‑domain blocking check using a domain expected to be malicious or parked.  
- WHOIS enrichment via a `whois_cache` table, with cache‑only lookup from the main analyzer and a separate batch enrichment script.  
- Per‑query logging into `dns_query_logs` and per‑server summary records into `server_analysis_results`.  
- Optional periodic execution via a systemd service and timer for automated measurements on Linux.  

---

## Project layout

- `main.py` – thin entrypoint; performs preflight checks, parses CLI arguments, prints a banner, and runs a single analysis cycle.  
- `analysis.py` – core orchestration for one analysis cycle over all DNS servers, including WHOIS cache stats and progress reporting.  
- `dns_checker.py` – `DNSChecker` class that runs recursion, latency, DNSSEC, malicious‑domain, and WHOIS (cache) checks for a single server IP.  
- `database.py` – PostgreSQL access layer: connects to the DB, creates tables, and provides methods to log queries, save server results, and manage `whois_cache`.  
- `models.py` – dataclasses (`DNSQueryLog`, `ServerResult`) representing per‑query and per‑server records stored in the database.  
- `utils.py` – helper functions to load DNS servers from JSON, get IST timestamps, detect system DNS servers, and obtain hostname/public IP.  
- `config.py` – central configuration for DB connection, test domains, timeouts, default input file, and batch sizes.  
- `whois.py` – optional standalone WHOIS enrichment script that populates `whois_cache` in batches using RDAP lookups.  
- `environment.py` – environment and preflight checks: loads `.env` and verifies required Python packages and DB credentials.  
- `cli.py` – command‑line helpers (argument parsing and startup banner).  
- `truncate_tables.py` – utility to truncate measurement tables in PostgreSQL when you want a clean slate.  
- `dns-analyzer.service` / `dns-analyzer.timer` – example systemd units for running the analyzer as a oneshot service every hour.  
- `install-dns-analyzer.sh` – helper for setting up a virtualenv, installing dependencies, and deploying the systemd units.  
- `in.json` – input file containing the list of DNS server IPs to analyze.  

---

## Requirements

- Python 3.9+ (recommended).  
- PostgreSQL instance reachable with the credentials defined in `.env`.  
- Python packages from `requirements.txt` (`dnspython`, `psycopg2`, `python-dotenv`, `ipwhois`, `pytz`, etc.).  

Install dependencies in a virtual environment:

```

python -m venv venv

# Linux/macOS

source venv/bin/activate

# Windows

venv\Scripts\activate

pip install -r requirements.txt

```

---

## Configuration

### Environment variables

Database connection details are configured via `.env` and loaded into the application configuration.  

Example `.env`:

```

DB_HOST=localhost
DB_PORT=5432
DB_NAME=dns_analyzer
DB_USER=postgres
DB_PASSWORD=your_password_here

```

Place `.env` in the repository root alongside `main.py`.  

### Test domains and general settings

The following parameters are defined in `config.py`:  

- `DNS_TIMEOUT` – per‑query timeout (seconds).  
- `RECURSION_TEST_DOMAIN` – A‑query domain to test recursion and RA flag.  
- `LATENCY_TEST_DOMAIN` – domain used for latency measurement.  
- `DNSSEC_TEST_DOMAIN` – domain used for DNSSEC validation.  
- `MALICIOUS_TEST_DOMAIN` – domain used to test malicious‑domain blocking.  
- `INPUT_FILE` – default JSON file containing servers (`in.json`).  

Edit `config.py` to adapt the analyzer to your measurement scenario.  

---

## Database schema (overview)

On initialization, the database layer creates the core tables if they do not exist.  

- `dns_query_logs`  
  - Stores one row per DNS query, including server IP, query type/name, flags, rcode, answer, TTL, response time, timestamp, and logical test type.  
- `whois_cache`  
  - Caches WHOIS data per `server_ip` (organization, ASN, ASN description, country, created/updated timestamps).  
- `server_analysis_results`  
  - Stores per‑server snapshots: recursion flags, latency, WHOIS fields, DNSSEC results, malicious‑blocking result, ISP‑assigned flag, responsiveness, and reliability classification.  

These tables are indexed on server IP and timestamps to support efficient querying.  

---

## Usage

### Single run (CLI)

Run a single analysis cycle using the default input file from `config.INPUT_FILE`:

```

python main.py

```

You can also specify a different input file and inter‑server delay:

```

python main.py --input in.json --delay 0.1

```

On each run:

1. The entrypoint performs preflight checks and parses CLI arguments.  
2. The analysis layer loads the server list from JSON and prepends system DNS resolvers if not already present.  
3. The analysis cycle logs WHOIS cache stats, then iterates over all servers.  
4. For each server, `DNSChecker.analyze()` runs recursion, latency, DNSSEC, malicious‑domain, and WHOIS‑cache checks, printing detailed step logs and a final summary.  
5. The database layer writes per‑query logs and per‑server results into PostgreSQL.  

---

## WHOIS enrichment

By design, the main analyzer uses the WHOIS cache only and does not perform live RDAP queries during analysis.  
To populate `whois_cache`, use the batch enrichment script `whois.py`.  

Example:

```

python whois.py --batch 50 --delay 1.0

```

Behavior:

- Selects up to `batch_size` distinct IPs that are present in `server_analysis_results` but not in `whois_cache`.  
- Performs RDAP lookups using `ipwhois.IPWhois.lookup_rdap()` and extracts organization, ASN, description, and country.  
- Inserts or updates rows in `whois_cache` and respects `delay` between lookups to avoid rate‑limiting.  

Run it repeatedly until the WHOIS stats report zero missing IPs.  

---

## Scheduling with systemd (Linux)

You can schedule periodic runs using the provided systemd units.  

1. Edit `dns-analyzer.service` to point to your project directory, virtualenv, and user:

```

[Service]
Type=oneshot
User=your-username
Group=your-username
WorkingDirectory=/home/your-username/dns-analyzer
Environment="PATH=/home/your-username/dns-analyzer/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=/home/your-username/dns-analyzer/.env
ExecStart=/home/your-username/dns-analyzer/venv/bin/python3 main.py --input in.json --delay 0.1

```

2. The `dns-analyzer.timer` unit defines when to run the service (for example, 5 minutes after boot, then 1 hour after each completion).  

3. Deploy and enable:

```

sudo cp dns-analyzer.service /etc/systemd/system/
sudo cp dns-analyzer.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns-analyzer.timer

```

This yields an hourly measurement loop driven by systemd rather than an internal loop mode.  

---

## Development notes

- For debugging, most detailed logs come from `DNSChecker` methods (`check_recursion`, `check_latency`, `check_dnssec`, `check_malicious_blocking`, `get_whois_info`, `analyze`).  
- Use `truncate_tables.py` in development to clear measurement data between experiments; this script operates directly on the PostgreSQL tables.  
- Because `main.py` is a thin wrapper, other tools (for example, a web dashboard) can import and reuse `analysis.run_analysis_cycle()` and the models without going through the CLI.  
```

