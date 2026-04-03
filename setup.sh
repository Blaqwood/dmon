#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${1:-.venv}"

echo ">>> Creating virtual environment in '${VENV_DIR}'..."
python3 -m venv "${VENV_DIR}"

# some distributions cannot use pip so install with apt in that case
sudo apt install python3 python3-watchdog python3-venv

echo ">>> Activating virtual environment..."
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

echo ">>> Upgrading pip..."
pip install --upgrade pip

echo ">>> Installing watchdog..."
pip install watchdog

source ${VENV_DIR}/bin/activate

python3 main.py
