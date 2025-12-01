#!/usr/bin/env bash
# run.sh
# Clone and run DNS Measurement System once, using shared PostgreSQL DB.
# DB credentials are read ONLY from a local .env file next to this script.

set -euo pipefail

REPO_URL="https://github.com/0x7D4/dns-measurement-system.git"
REPO_DIR="dns-measurement-system"
VENV_DIR="venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------------
# 1. OS-specific prerequisites (DietPi / Debian / Raspberry Pi)
# -----------------------------------------------------------------------------
echo "[*] Detecting OS..."
OS_NAME="$(uname -s || echo unknown)"

if [[ "$OS_NAME" == "Linux" ]]; then
    echo "[*] Checking for prerequisites (python3-venv, libpq-dev, traceroute)..."

    # python3-venv
    if ! dpkg -s python3-venv >/dev/null 2>&1; then
        echo " Package python3-venv not installed."
        echo " Trying: sudo apt-get install -y python3-venv"
        sudo apt-get install -y python3-venv || {
            echo " WARNING: Failed to install python3-venv. Virtualenv creation may fail."
        }
    fi

    # libpq-dev (Required for psycopg2)
    if ! dpkg -s libpq-dev >/dev/null 2>&1; then
        echo " Package libpq-dev not installed (required for psycopg2)."
        echo " Trying: sudo apt-get install -y libpq-dev"
        sudo apt-get install -y libpq-dev || {
            echo " WARNING: Failed to install libpq-dev. Python dependency installation may fail."
        }
    fi

    # traceroute
    if ! command -v traceroute >/dev/null 2>&1; then
        echo " 'traceroute' not found."
        echo " Trying: sudo apt-get install -y traceroute"
        sudo apt-get install -y traceroute || {
            echo " WARNING: Failed to install traceroute. Traceroute tests will be skipped or fail."
        }
    fi

else
    echo "[*] Non-Linux OS detected (${OS_NAME})."
    echo "    On Windows, 'tracert' is built-in and no package install is needed."
fi

# -----------------------------------------------------------------------------
# 2. Clone repo
# -----------------------------------------------------------------------------
echo "[*] Cloning repository..."
if [ -d "$REPO_DIR" ]; then
    echo "    Repo directory '$REPO_DIR' already exists, skipping git clone."
else
    git clone "$REPO_URL"
fi

# -----------------------------------------------------------------------------
# 3. Load DB credentials from .env (now required to proceed)
# -----------------------------------------------------------------------------
if [ -f "${SCRIPT_DIR}/.env" ]; then
    echo "[*] Loading DB credentials from ${SCRIPT_DIR}/.env"
    # Export only DB_* lines, strip comments
    # shellcheck disable=SC2046
    export $(grep -E '^DB_' "${SCRIPT_DIR}/.env" | sed 's/#.*//g' | xargs || true)
else
    echo "ERROR: .env with DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD is required next to run.sh to run the tool."
    exit 1
fi

# Fail fast if any DB_* is missing
DB_HOST="${DB_HOST:?DB_HOST not set in .env}"
DB_PORT="${DB_PORT:?DB_PORT not set in .env}"
DB_NAME="${DB_NAME:?DB_NAME not set in .env}"
DB_USER="${DB_USER:?DB_USER not set in .env}"
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD not set in .env}"

# -----------------------------------------------------------------------------
# 4. Set up venv and install dependencies
# -----------------------------------------------------------------------------
cd "$REPO_DIR"

echo "[*] Setting up Python virtual environment..."
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    echo "    Virtualenv '$VENV_DIR' already exists, reusing."
else
    echo "    Creating (or re-creating) virtualenv in '$VENV_DIR'..."
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# -----------------------------------------------------------------------------
# 5. Write .env inside repo for the app (from loaded vars)
# -----------------------------------------------------------------------------
echo "[*] Writing .env for shared PostgreSQL inside repo..."
cat > .env <<EOF
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
EOF

# -----------------------------------------------------------------------------
# 6. Run the tool (single run)
# -----------------------------------------------------------------------------
echo "[*] Running DNS Measurement System once..."
python3 main.py

echo "[*] Done."
