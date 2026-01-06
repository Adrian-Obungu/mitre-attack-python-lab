#!/bin/bash

# --- Foundation Setup Script for MITRE ATT&CK Python Lab ---
# This script sets up a minimal Python virtual environment, installs essential dependencies,
# creates necessary configuration files (.env, .vscode/settings.json), and updates .gitignore.
# It's designed to be run in Git Bash on Windows.

set -e # Exit immediately if a command exits with a non-zero status

# Define paths
PROJECT_ROOT=$(pwd)
VENV_DIR="${PROJECT_ROOT}/venv"
PYTHON_BIN="${VENV_DIR}/Scripts/python.exe" # For Windows, under Git Bash

echo "--- Starting Foundation Environment Setup ---"
echo "Project Root: ${PROJECT_ROOT}"

# 1. Create and activate virtual environment
if [ ! -d "${VENV_DIR}" ]; then
    echo "Creating virtual environment at ${VENV_DIR}..."
    /usr/bin/python -m venv "${VENV_DIR}"
else
    echo "Virtual environment already exists at ${VENV_DIR}."
fi

echo "Activating virtual environment (for script duration)..."
# Directly use venv Python for subsequent commands
# This ensures that pip and python commands use the venv
export PATH="${VENV_DIR}/Scripts:$PATH"

# 2. Install essential dependencies
echo "Installing/Upgrading essential dependencies..."
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn dnslib prometheus-client requests python-dotenv tabulate

echo "Essential dependencies installed."

# 3. Create or update .env file
ENV_FILE="${PROJECT_ROOT}/.env"
echo "Creating/Updating ${ENV_FILE}..."
cat <<EOF > "${ENV_FILE}"
# .env file for MITRE ATT&CK Python Lab
# Test API keys for local development and testing
API_KEY="test-key-123"
ABUSEIPDB_API_KEY="mock_abuseipdb_key_for_testing"
VIRUSTOTAL_API_KEY="mock_virustotal_key_for_testing"
MOCK_MODE=true
EOF
echo ".env file created/updated."

# 4. Create or update .vscode/settings.json
VSCODE_DIR="${PROJECT_ROOT}/.vscode"
VSCODE_SETTINGS_FILE="${VSCODE_DIR}/settings.json"

mkdir -p "${VSCODE_DIR}" # Ensure .vscode directory exists

echo "Creating/Updating ${VSCODE_SETTINGS_FILE}..."
cat <<EOF > "${VSCODE_SETTINGS_FILE}"
{
    "python.pythonPath": "${VENV_DIR}/Scripts/python.exe",
    "python.analysis.extraPaths": ["./src"],
    "python.envFile": "${workspaceFolder}/.env"
}
EOF
echo ".vscode/settings.json created/updated. You may need to restart VS Code."


# 5. Update .gitignore
GITIGNORE_FILE="${PROJECT_ROOT}/.gitignore"
echo "Updating ${GITIGNORE_FILE}..."

# Remove potentially conflicting lines if they exist and then add the new structure
if grep -q "logs/honeyresolver.log" "${GITIGNORE_FILE}"; then
  sed -i '/logs\/honeyresolver.log/d' "${GITIGNORE_FILE}"
fi
if grep -q "\*\.log" "${GITIGNORE_FILE}"; then
  sed -i '/\*\.log/d' "${GITIGNORE_FILE}"
fi
if grep -q "logs/" "${GITIGNORE_FILE}"; then
  sed -i '/logs\//!d' "${GITIGNORE_FILE}" # This might be too aggressive, better to check for line and append if not there
fi

# Ensure specific lines are present (append if not found)
ensure_gitignore_line() {
    local line="$1"
    if ! grep -qxF "$line" "${GITIGNORE_FILE}"; then
        echo "$line" >> "${GITIGNORE_FILE}"
    fi
}

ensure_gitignore_line "# Python"
ensure_gitignore_line "__pycache__/"
ensure_gitignore_line "*.py[cod]"
ensure_gitignore_line "venv/"
ensure_gitignore_line ".env"
ensure_gitignore_line "logs/"
ensure_gitignore_line "*.log"

echo ".gitignore updated."

echo "--- Foundation Environment Setup Complete ---"
echo "Please run 'chmod +x setup_foundation.sh' then './setup_foundation.sh' to execute."
echo "After running, restart VS Code to pick up new settings."
