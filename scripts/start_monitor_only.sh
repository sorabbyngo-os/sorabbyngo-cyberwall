#!/bin/bash
# Safe mode — monitor and alert, no firewall rules applied
python3 cyberwall_daemon.py --config configs/cyberwall.yaml --monitor-only
