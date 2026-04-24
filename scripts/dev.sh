#!/usr/bin/env bash
# Sorabbyngo Cyberwall — Dev Environment Launcher
# Usage: bash scripts/dev.sh [--test | --shell | --re | --run]
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/.venv"

info()    { echo -e "${CYAN}[dev]${NC} $*"; }
success() { echo -e "${GREEN}[dev]${NC} $*"; }
warn()    { echo -e "${YELLOW}[dev]${NC} $*"; }

[[ -d "$VENV" ]] && source "$VENV/bin/activate" && info "venv active" || warn "Using system Python"
cd "$REPO_ROOT"

case "${1:---run}" in
    --test)
        info "Running tests..."
        pytest tests/ -v --cov=cyberwall --cov-report=term-missing
        ;;
    --shell)
        info "Cyberwall REPL..."
        python3 -c "
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.threat_scorer import score_event
from cyberwall.core.policy_engine import PolicyEngine
print('Modules loaded: EventBus, ThreatEvent, ThreatLevel, score_event, PolicyEngine')
import code; code.interact(local=locals())
"
        ;;
    --re)
        info "RE toolkit REPL..."
        python3 -c "
import capstone, keystone, unicorn, lief, pwn
from elftools.elf.elffile import ELFFile
print('RE toolkit loaded — capstone / keystone / unicorn / lief / pwntools')
import code; code.interact(local=locals())
"
        ;;
    --run|*)
        info "Monitor-only mode (no firewall rules)..."
        python3 cyberwall_daemon.py --monitor-only --no-root-checks
        ;;
esac
