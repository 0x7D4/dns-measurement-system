#!/bin/bash
set -e

# Configuration
REPO_URL="https://github.com/0x7D4/dns-measurement-system.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="dns-analyzer"
LOG_FILE="$SCRIPT_DIR/analyzer.log"

touch "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Starting" | tee -a "$LOG_FILE"

# Install dependencies
sudo apt update
sudo apt install -y git python3-venv libpq-dev traceroute

# Update repository
cd "$SCRIPT_DIR"
git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true

# Setup Python environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q
    ./venv/bin/pip install -r requirements.txt -q
fi

# Verify input file
if [ ! -f "test.json" ]; then
    echo "ERROR: test.json not found" | tee -a "$LOG_FILE"
    exit 1
fi

# Run analyzer
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer process starting..." | tee -a "$LOG_FILE"
exec "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/main.py" --delay 0