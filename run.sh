#!/bin/bash
set -e

# Configuration
REPO_URL="https://github.com/0x7D4/dns-measurement-system.git"
REPO_DIR="dns-measurement-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="dns-analyzer"
LOG_FILE="./analyzer.log"

touch "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Starting" | tee -a "$LOG_FILE"

# Install dependencies
sudo apt update
sudo apt install -y git python3-venv libpq-dev traceroute

# Clone or update repository
cd "$SCRIPT_DIR"
if [ -d "$REPO_DIR" ]; then
    cd "$REPO_DIR"
    git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true
    cd "$SCRIPT_DIR"
else
    git clone "$REPO_URL" "$REPO_DIR"
fi

# Load environment
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found" | tee -a "$LOG_FILE"
    exit 1
fi

set -a
source "$SCRIPT_DIR/.env"
set +a

# Setup Python environment
cd "$SCRIPT_DIR/$REPO_DIR"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q
    ./venv/bin/pip install -r requirements.txt -q
fi

cp "$SCRIPT_DIR/.env" .env

# Verify input file
if [ ! -f "test.json" ]; then
    echo "ERROR: test.json not found" | tee -a "$LOG_FILE"
    exit 1
fi

# Run analyzer in background with nohup
nohup ./venv/bin/python3 main.py --delay 0 >> "$LOG_FILE" 2>&1 &
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer process started (PID: $!)" | tee -a "$LOG_FILE"

# Setup systemd (first run only)
if [ ! -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    echo "Installing systemd service..." | tee -a "$LOG_FILE"
    
    # Create service file with dynamic paths
    sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null <<EOF
[Unit]
Description=DNS Server Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=$SCRIPT_DIR/.env
WorkingDirectory=$SCRIPT_DIR/$REPO_DIR
ExecStart=/bin/bash $SCRIPT_DIR/run.sh
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    # Create timer file with dynamic service name
    sudo tee "/etc/systemd/system/${SERVICE_NAME}.timer" > /dev/null <<EOF
[Unit]
Description=DNS Analyzer Timer - Runs every 2 hours
Requires=${SERVICE_NAME}.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=2h
Persistent=true
Unit=${SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "${SERVICE_NAME}.timer"
    sudo systemctl start "${SERVICE_NAME}.timer"
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Setup Completed" | tee -a "$LOG_FILE"