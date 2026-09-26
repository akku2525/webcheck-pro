#!/usr/bin/env bash
# WebCheck Pro installer — by Akash Mishra
set -e

echo "=================================================="
echo "   WebCheck Pro Installer — by Akash Mishra"
echo "=================================================="

if ! command -v python3 &> /dev/null; then
    echo "[!] python3 not found. Installing..."
    sudo apt update && sudo apt install -y python3 python3-pip
fi

if ! command -v traceroute &> /dev/null; then
    echo "[*] Installing traceroute (required for the traceroute module)..."
    sudo apt update && sudo apt install -y traceroute
fi

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

chmod +x webcheck.py

echo ""
echo "[+] Installation complete!"
echo ""
echo "Run it with:"
echo "    python3 webcheck.py -u example.com"
echo ""
echo "Optional: create a system-wide alias:"
echo "    sudo ln -sf \$(pwd)/webcheck.py /usr/local/bin/webcheck"
echo "    then just run: webcheck -u example.com"
echo ""
