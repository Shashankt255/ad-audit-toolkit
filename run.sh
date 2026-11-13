#!/bin/bash
echo "============================================"
echo "  AD Audit Toolkit v1.0.0"
echo "  Active Directory Security Assessment"
echo "============================================"
echo

if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found. Install Python 3.9+"
    exit 1
fi

echo "[*] Installing dependencies..."
pip3 install -r "$(dirname "$0")/requirements.txt" --quiet 2>/dev/null

echo "[*] Starting assessment..."
echo
python3 "$(dirname "$0")/ad_audit.py" "$@"
