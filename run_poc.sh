#!/usr/bin/env bash
#
# Self-contained proof of concept for spreadsheet formula injection in the
# Static Analysis Results Parser (SARP).
#
# It clones SARP at the tested release, builds a virtualenv, runs SARP against
# a malicious ESLint result file to produce both CSV and XLSX reports, then
# verifies that the attacker-controlled fields became live formulas.
#
# Non-destructive: the payloads are arithmetic markers (=1+2, =2*3, =IMSUM(4,5)).
# Nothing is executed against a live spreadsheet; verify.py only inspects the
# saved output. See README.md for the weaponized payloads and the threat model.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${HERE}/.work"
SARP_REPO="https://github.com/DevinPatel72/Static-Analysis-Results-Parser.git"
SARP_TAG="v2.11.3"

mkdir -p "${WORK}"
cd "${WORK}"

# 1. Get SARP at the tested version.
if [ ! -d "${WORK}/sarp/.git" ]; then
  git clone --depth 1 --branch "${SARP_TAG}" "${SARP_REPO}" sarp
fi

# 2. Virtualenv with SARP's runtime deps needed for CSV + XLSX output.
if [ ! -d "${WORK}/venv" ]; then
  python3 -m venv "${WORK}/venv"
fi
# shellcheck disable=SC1091
. "${WORK}/venv/bin/activate"
pip install -q --upgrade pip
pip install -q openpyxl matplotlib requests python-dateutil

# 3. Run SARP against the malicious ESLint report -> CSV and XLSX.
cd "${WORK}/sarp/src"
python parse-cli.py -i eslint "${HERE}/malicious-eslint-report.json" \
  -o "${WORK}/out.csv"  --format csv   --disable-progressbar
python parse-cli.py -i eslint "${HERE}/malicious-eslint-report.json" \
  -o "${WORK}/out.xlsx" --format excel --disable-progressbar

# 4. Show the raw CSV and verify the formula cells.
echo
echo "===== raw CSV output ====="
cat "${WORK}/out.csv"
echo
echo "===== verification ====="
python "${HERE}/verify.py" "${WORK}/out.xlsx" "${WORK}/out.csv"
