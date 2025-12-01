#!/usr/bin/env bash
#
# run.sh - DNS Server Analyzer Runner
# Runs a single analysis cycle, called by systemd timer
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
INPUT_FILE="${SCRIPT_DIR}/in.json"
DELAY=0  # Delay between servers (0 for fastest)

# -----------------------------------------------------------------------------
# 1. Check prerequisites (DietPi / Debian)
# -----------------------------------------------------------------------------

echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Starting"

if [[ "$(uname -s)" == "Linux" ]]; then
    # Check for required packages
    MISSING_PKGS=()
    
    if ! dpkg -s python3-venv >/dev/null 2>&1; then
        MISSING_PKGS+=("python3-venv")
    fi
    
    if ! dpkg -s libpq-dev >/dev/null 2>&1; then
        MISSING_PKGS+=("libpq-dev")
    fi
    
    if ! command -v traceroute >/dev/null 2>&1; then
        MISSING_PKGS+=("traceroute")
    fi
    
    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo "[*] Installing missing packages: ${MISSING_PKGS[*]}"
        apt-get update -qq
        apt-get install -y "${MISSING_PKGS[@]}"
    fi
fi

# -----------------------------------------------------------------------------
# 2. Load environment from .env
# -----------------------------------------------------------------------------

if [ -f "${SCRIPT_DIR}/.env" ]; then
    echo "[*] Loading configuration from .env"
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
else
    echo "ERROR: .env file not found at ${SCRIPT_DIR}/.env"
    echo "Create .env with DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD"
    exit 1
fi

# Verify required variables
: "${DB_HOST:?DB_HOST not set in .env}"
: "${DB_PORT:?DB_PORT not set in .env}"
: "${DB_NAME:?DB_NAME not set in .env}"
: "${DB_USER:?DB_USER not set in .env}"
: "${DB_PASSWORD:?DB_PASSWORD not set in .env}"

# -----------------------------------------------------------------------------
# 3. Setup Python virtual environment
# -----------------------------------------------------------------------------

cd "$SCRIPT_DIR"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    echo "[*] Installing dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install -r requirements.txt --quiet
else
    # Check if requirements need updating (optional)
    if [ requirements.txt -nt "$VENV_DIR/pyvenv.cfg" ]; then
        echo "[*] Updating dependencies..."
        "$VENV_DIR/bin/pip" install -r requirements.txt --quiet
        touch "$VENV_DIR/pyvenv.cfg"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Verify input file exists
# -----------------------------------------------------------------------------

if [ ! -f "$INPUT_FILE" ]; then
    echo "ERROR: Input file not found: $INPUT_FILE"
    exit 1
fi

# Count IPs in input file
IP_COUNT=$(python3 -c "
import json
with open('$INPUT_FILE') as f:
    data = json.load(f)
    if isinstance(data, list):
        print(len(data))
    elif isinstance(data, dict) and 'servers' in data:
        print(len(data['servers']))
    else:
        print(0)
" 2>/dev/null || echo "0")

echo "[*] Found $IP_COUNT DNS servers in $INPUT_FILE"

# -----------------------------------------------------------------------------
# 5. Run DNS Analyzer (single cycle)
# -----------------------------------------------------------------------------

echo "[*] Executing DNS Analyzer..."
echo "    DB: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "    Input: $INPUT_FILE"
echo "    Delay: ${DELAY}s per server"
echo ""

# Run the analyzer
"$VENV_DIR/bin/python3" main.py \
    --input "$INPUT_FILE" \
    --delay "$DELAY" \
    2>&1

EXIT_CODE=$?

# -----------------------------------------------------------------------------
# 6. Report status
# -----------------------------------------------------------------------------

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Completed successfully"
    exit 0
else
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi
