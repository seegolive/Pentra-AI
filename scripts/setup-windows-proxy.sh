#!/usr/bin/env bash
# setup-windows-proxy.sh
# Run from WSL2 terminal. Launches the PowerShell script elevated (UAC prompt will appear).
# Usage: bash scripts/setup-windows-proxy.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS1_SCRIPT="$SCRIPT_DIR/setup-windows-proxy.ps1"

# Convert WSL path to Windows path
WIN_PATH=$(wslpath -w "$PS1_SCRIPT")

echo "[*] Launching elevated PowerShell (UAC prompt may appear)..."
powershell.exe -Command "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File \"$WIN_PATH\"' -Wait" 2>/dev/null

echo ""
echo "[*] Testing from WSL2..."
sleep 2

for PORT in 5174 8001; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://localhost:$PORT" 2>/dev/null)
    if [[ "$STATUS" == "200" || "$STATUS" == "404" || "$STATUS" == "307" ]]; then
        echo "    localhost:$PORT → OK ($STATUS)"
    else
        echo "    localhost:$PORT → TIMEOUT/ERROR (start services first)"
    fi
done
