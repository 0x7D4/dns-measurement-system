#!/usr/bin/env bash
# run.sh
# Clone and run DNS Measurement System once, using shared PostgreSQL DB.
# DB credentials are read ONLY from a local .env file next to this script.

set -euo pipefail

REPO_URL="https://github.com/0x7D4/dns-measurement-system.git"
REPO_DIR="dns-measurement-system"
VENV_DIR="venv"

# -----------------------------------------------------------------------------
# Load DB credentials from .env (required)
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${SCRIPT_DIR}/.env" ]; then
  echo "[*] Loading DB credentials from ${SCRIPT_DIR}/.env"
  # Export only DB_* lines, strip comments
  # shellcheck disable=SC2046
  export $(grep -E '^DB_' "${SCRIPT_DIR}/.env" | sed 's/#.*//g' | xargs || true)
else
  echo "ERROR: .env with DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD is required next to run.sh"
  exit 1
fi

# Fail fast if any DB_* is missing
DB_HOST="${DB_HOST:?DB_HOST not set in .env}"
DB_PORT="${DB_PORT:?DB_PORT not set in .env}"
DB_NAME="${DB_NAME:?DB_NAME not set in .env}"
DB_USER="${DB_USER:?DB_USER not set in .env}"
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD not set in .env}"

# -----------------------------------------------------------------------------
# OS-specific prerequisites (DietPi / Debian / Raspberry Pi)
# -----------------------------------------------------------------------------
echo "[*] Detecting OS..."
OS_NAME="$(uname -s || echo unknown)"

if [[ "$OS_NAME" == "Linux" ]]; then
  echo "[*] Checking for python3-venv and traceroute (no automatic apt-get update)..."

  # python3-venv
  if ! dpkg -s python3-venv >/dev/null 2>&1; then
    echo "    Package python3-venv not installed."
    echo "    Trying: sudo apt-get install -y python3-venv"
    echo "    If this fails with repository errors, please fix /etc/apt/sources.list* on DietPi and rerun."
    sudo apt-get install -y python3-venv || {
      echo "    WARNING: Failed to install python3-venv. Virtualenv creation may fail."
    }
  fi

  # traceroute
  if ! command -v traceroute >/dev/null 2>&1; then
    echo "    'traceroute' not found."
    echo "    Trying: sudo apt-get install -y traceroute"
    sudo apt-get install -y traceroute || {
      echo "    WARNING: Failed to install traceroute. Traceroute tests will be skipped or fail."
    }
  fi
else
  echo "[*] Non-Linux OS detected (${OS_NAME})."
  echo "    On Windows, 'tracert' is built-in and no package install is needed."
fi

# -----------------------------------------------------------------------------
# Clone repo and set up venv
# -----------------------------------------------------------------------------
echo "[*] Cloning repository..."
if [ -d "$REPO_DIR" ]; then
  echo "    Repo directory '$REPO_DIR' already exists, skipping git clone."
else
  git clone "$REPO_URL"
fi

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
# Write .env inside repo for the app (from loaded vars)
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
# Run analyzer
# -----------------------------------------------------------------------------
echo "[*] Running DNS Measurement System once..."
python main.py --input in.json --delay 0.1

echo "[*] Done. Results are stored in PostgreSQL at ${DB_HOST}:${DB_PORT}/${DB_NAME} (user ${DB_USER})."
