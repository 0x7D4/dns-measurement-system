#!/usr/bin/env bash
#
# run.sh - DNS Server Analyzer Runner
# Clones repo, runs analyzer, sets up and ensures systemd timer is running
#

set -euo pipefail

# Configuration
REPO_URL="https://github.com/0x7D4/dns-measurement-system.git"
REPO_DIR="dns-measurement-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/venv"
DELAY=0

# Systemd markers
SYSTEMD_SETUP_MARKER="${SCRIPT_DIR}/.systemd_installed"
SERVICE_NAME="dns-analyzer"

# -----------------------------------------------------------------------------
# 1. Check prerequisites (DietPi / Debian)
# -----------------------------------------------------------------------------

echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Starting"

if [[ "$(uname -s)" == "Linux" ]]; then
    MISSING_PKGS=()
    
    if ! command -v git >/dev/null 2>&1; then
        MISSING_PKGS+=("git")
    fi
    
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
# 2. Clone or update repository
# -----------------------------------------------------------------------------

cd "$SCRIPT_DIR"

if [ -d "$REPO_DIR" ]; then
    echo "[*] Repository directory exists, pulling latest changes..."
    cd "$REPO_DIR"
    git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || echo "  (git pull skipped)"
    cd "$SCRIPT_DIR"
else
    echo "[*] Cloning repository from $REPO_URL..."
    git clone "$REPO_URL" "$REPO_DIR"
fi

# -----------------------------------------------------------------------------
# 3. Load environment from .env (must exist)
# -----------------------------------------------------------------------------

if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    echo "ERROR: .env file not found at ${SCRIPT_DIR}/.env"
    echo ""
    echo "Please create .env with your database configuration:"
    echo "  DB_HOST=localhost"
    echo "  DB_PORT=5432"
    echo "  DB_NAME=dns_analyzer"
    echo "  DB_USER=dns_user"
    echo "  DB_PASSWORD=your_secure_password"
    echo ""
    exit 1
fi

echo "[*] Loading configuration from ${SCRIPT_DIR}/.env"
set -a
source "${SCRIPT_DIR}/.env"
set +a

# Verify required variables
: "${DB_HOST:?DB_HOST not set in .env}"
: "${DB_PORT:?DB_PORT not set in .env}"
: "${DB_NAME:?DB_NAME not set in .env}"
: "${DB_USER:?DB_USER not set in .env}"
: "${DB_PASSWORD:?DB_PASSWORD not set in .env}"

# -----------------------------------------------------------------------------
# 4. Setup Python virtual environment
# -----------------------------------------------------------------------------

cd "$SCRIPT_DIR/$REPO_DIR"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    echo "[*] Installing dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install -r requirements.txt --quiet
else
    if [ requirements.txt -nt "$VENV_DIR/pyvenv.cfg" ]; then
        echo "[*] Updating dependencies..."
        "$VENV_DIR/bin/pip" install -r requirements.txt --quiet
        touch "$VENV_DIR/pyvenv.cfg"
    fi
fi

# -----------------------------------------------------------------------------
# 5. Copy .env into repo
# -----------------------------------------------------------------------------

echo "[*] Copying .env into repository..."
cp "${SCRIPT_DIR}/.env" .env

# -----------------------------------------------------------------------------
# 6. Verify input file exists
# -----------------------------------------------------------------------------

if [ ! -f "test.json" ]; then
    echo "ERROR: test.json not found in repository"
    exit 1
fi

IP_COUNT=$(python3 -c "
import json
with open('test.json') as f:
    data = json.load(f)
    if isinstance(data, list):
        print(len(data))
    elif isinstance(data, dict) and 'servers' in data:
        print(len(data['servers']))
    else:
        print(0)
" 2>/dev/null || echo "0")

echo "[*] Found $IP_COUNT DNS servers in test.json"

# -----------------------------------------------------------------------------
# 7. Setup systemd (on first run only)
# -----------------------------------------------------------------------------

setup_systemd() {
    echo ""
    echo "=========================================================================="
    echo "Setting up systemd service and timer..."
    echo "=========================================================================="
    
    # Check if systemd files exist in repo
    if [ ! -f "${SERVICE_NAME}.service" ] || [ ! -f "${SERVICE_NAME}.timer" ]; then
        echo "WARNING: Systemd files not found in repository"
        echo "  Expected: ${SERVICE_NAME}.service and ${SERVICE_NAME}.timer"
        echo "  Skipping systemd setup"
        return 1
    fi
    
    # Update paths in service file to match current installation
    echo "[*] Updating service file paths..."
    sed "s|WorkingDirectory=.*|WorkingDirectory=${SCRIPT_DIR}|g" \
        "${SERVICE_NAME}.service" | \
    sed "s|ExecStart=.*|ExecStart=/bin/bash ${SCRIPT_DIR}/run.sh|g" \
        > "/tmp/${SERVICE_NAME}.service"
    
    # Copy files to systemd
    echo "[*] Installing systemd files..."
    cp "/tmp/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service"
    cp "${SERVICE_NAME}.timer" "/etc/systemd/system/${SERVICE_NAME}.timer"
    
    # Set permissions
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.timer"
    
    # Reload systemd
    echo "[*] Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Enable timer
    echo "[*] Enabling timer..."
    systemctl enable "${SERVICE_NAME}.timer"
    
    # Create marker file
    touch "${SYSTEMD_SETUP_MARKER}"
    
    echo "[*] Systemd files installed"
    
    return 0
}

# -----------------------------------------------------------------------------
# 8. Ensure timer is running (on every run)
# -----------------------------------------------------------------------------

ensure_timer_running() {
    # Check if timer service file exists
    if [ ! -f "/etc/systemd/system/${SERVICE_NAME}.timer" ]; then
        return 1
    fi
    
    # Check if timer is active
    if systemctl is-active --quiet "${SERVICE_NAME}.timer"; then
        echo "[*] Timer is already running"
        return 0
    fi
    
    echo "[*] Timer is not running, starting it now..."
    systemctl start "${SERVICE_NAME}.timer"
    
    # Verify it started
    if systemctl is-active --quiet "${SERVICE_NAME}.timer"; then
        echo "[*] ✅ Timer started successfully"
        
        # Show next run time
        echo ""
        systemctl list-timers "${SERVICE_NAME}.timer" --no-pager 2>/dev/null || true
        echo ""
        
        return 0
    else
        echo "[*] ⚠️  Failed to start timer"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# 9. Run DNS Analyzer
# -----------------------------------------------------------------------------

echo "[*] Executing DNS Analyzer..."
echo "    DB: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "    Input: test.json"
echo "    Delay: ${DELAY}s per server"
echo ""

# Export DB credentials
export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD

# Run the analyzer
"$VENV_DIR/bin/python3" main.py \
    --input test.json \
    --delay "$DELAY" \
    2>&1

EXIT_CODE=$?

# -----------------------------------------------------------------------------
# 10. Post-run actions
# -----------------------------------------------------------------------------

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Completed successfully"
    
    # Setup systemd on first successful run
    if [ ! -f "${SYSTEMD_SETUP_MARKER}" ]; then
        if setup_systemd; then
            echo "[*] First run: Systemd installed"
        fi
    fi
    
    # Always ensure timer is running (on every run)
    echo ""
    ensure_timer_running
    
    echo ""
    echo "=========================================================================="
    echo "Useful commands:"
    echo "  systemctl status ${SERVICE_NAME}.timer    # Check timer status"
    echo "  systemctl list-timers ${SERVICE_NAME}.timer  # Next run time"
    echo "  journalctl -u ${SERVICE_NAME}.service -f  # View live logs"
    echo "  systemctl stop ${SERVICE_NAME}.timer      # Stop timer"
    echo "=========================================================================="
    echo ""
    
    exit 0
else
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS Analyzer - Failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi
