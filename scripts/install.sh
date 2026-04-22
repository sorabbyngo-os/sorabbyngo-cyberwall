#!/bin/bash
set -e
echo "[cyberwall] Installing Sorabbyngo Cyberwall..."

# System deps
sudo apt-get install -y nftables python3 python3-pip

# Python deps
pip install -r requirements.txt --break-system-packages

# Create runtime dirs
sudo mkdir -p /var/lib/cyberwall/quarantine
sudo mkdir -p /var/log/sorabbyngo

echo "[cyberwall] Installation complete."
echo "[cyberwall] Run: sudo python3 cyberwall_daemon.py --config configs/cyberwall.yaml"
