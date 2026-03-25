#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${1:-.venv}"

echo ">>> Creating virtual environment in '${VENV_DIR}'..."
python3 -m venv "${VENV_DIR}"

echo ">>> Activating virtual environment..."
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

echo ">>> Upgrading pip..."
pip install --upgrade pip

echo ">>> Installing watchdog..."
pip install watchdog

sudo apt install python3-watchdog

source ${VENV_DIR}/bin/activate

python3 main.py
