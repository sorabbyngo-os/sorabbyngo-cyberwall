#!/bin/bash
# ============================================================================
# Sorabbyngo Cyberwall — Production Installer
# Supports: Ubuntu 20.04+, Debian 11+, Kali
# Modes:    --standalone (no NATS, no Ollama, no Sorabbyngo OS required)
#           --full       (full stack with NATS + AI analyzer)
#           --monitor-only (no firewall rules — safe on production)
# Usage:
#   sudo bash scripts/install.sh --standalone
#   sudo bash scripts/install.sh --full
#   sudo bash scripts/install.sh --standalone --monitor-only
# ============================================================================
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="standalone"
MONITOR_ONLY=false
INSTALL_DIR="/opt/sorabbyngo/cyberwall"
CONFIG_DIR="/etc/sorabbyngo"
LOG_DIR="/var/log/sorabbyngo"
DATA_DIR="/var/lib/cyberwall"
SERVICE_USER="cyberwall"
PYTHON="python3"
SKIP_SERVICE=false
SKIP_INTEL=false
NO_COLOR=false

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}── $* ──${NC}"; }

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --standalone)   MODE="standalone"; shift ;;
        --full)         MODE="full"; shift ;;
        --monitor-only) MONITOR_ONLY=true; shift ;;
        --skip-service) SKIP_SERVICE=true; shift ;;
        --skip-intel)   SKIP_INTEL=true; shift ;;
        --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
        --no-color)     NO_COLOR=true; shift ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [--standalone|--full] [--monitor-only]"
            echo "  --standalone    No NATS/Ollama required (default)"
            echo "  --full          Install NATS + enable AI analyzer"
            echo "  --monitor-only  No firewall rules (safe on live systems)"
            echo "  --skip-service  Don't install systemd service"
            echo "  --skip-intel    Skip threat intel import"
            exit 0 ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Run as root: sudo bash scripts/install.sh"
    exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║       Sorabbyngo Cyberwall — Production Installer        ║
║       AI-native firewall · Offline-first · Africa-built  ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo "  Mode         : $MODE"
echo "  Monitor only : $MONITOR_ONLY"
echo "  Install dir  : $INSTALL_DIR"
echo "  Config dir   : $CONFIG_DIR"
echo ""

# ── OS detection ──────────────────────────────────────────────────────────────
section "Detecting OS"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME="${NAME:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    info "Detected: $OS_NAME $OS_VERSION"
else
    warn "Cannot detect OS — assuming Debian-based"
    OS_NAME="Unknown"
fi

# Check for systemd
if ! command -v systemctl &>/dev/null; then
    warn "systemd not found — skipping service installation"
    SKIP_SERVICE=true
fi

# ── System dependencies ───────────────────────────────────────────────────────
section "Installing system dependencies"

apt-get update -qq
PKGS="python3 python3-pip nftables iproute2 procps curl"
[[ "$MODE" == "full" ]] && PKGS="$PKGS nats-server"

apt-get install -y $PKGS 2>&1 | grep -E "^(Get|Inst|Err)" || true
info "System packages installed"

# Python version check
PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
if [[ $PY_MAJOR -lt 3 ]] || [[ $PY_MAJOR -eq 3 && $PY_MINOR -lt 11 ]]; then
    warn "Python $PY_VERSION detected — 3.11+ recommended"
else
    info "Python $PY_VERSION ✓"
fi

# ── Create service user ───────────────────────────────────────────────────────
section "Setting up service user"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "Sorabbyngo Cyberwall" "$SERVICE_USER"
    info "Created user: $SERVICE_USER"
else
    info "User $SERVICE_USER already exists"
fi

# ── Create directories ────────────────────────────────────────────────────────
section "Creating runtime directories"
for dir in \
    "$INSTALL_DIR" \
    "$CONFIG_DIR" \
    "$LOG_DIR" \
    "$DATA_DIR" \
    "$DATA_DIR/quarantine" \
    "$DATA_DIR/signatures"; do
    mkdir -p "$dir"
    info "Created: $dir"
done

# Secure quarantine
chmod 700 "$DATA_DIR/quarantine"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
info "Directory permissions set"

# ── Install Python dependencies ───────────────────────────────────────────────
section "Installing Python dependencies"
pip install \
    nats-py>=2.6.0 \
    psutil>=5.9.0 \
    watchdog>=4.0.0 \
    pyyaml>=6.0.1 \
    cryptography>=42.0.0 \
    cachetools>=5.3.0 \
    --break-system-packages -q

# Optional: yara-python
if pip install yara-python --break-system-packages -q 2>/dev/null; then
    info "yara-python installed (full YARA scanning enabled)"
else
    warn "yara-python unavailable — using built-in pattern engine (fully functional)"
fi

info "Python dependencies installed"

# ── Copy application files ────────────────────────────────────────────────────
section "Installing Cyberwall"

# Detect source dir (script runs from repo root or scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cp -r "$REPO_DIR/cyberwall"        "$INSTALL_DIR/"
cp    "$REPO_DIR/cyberwall_daemon.py" "$INSTALL_DIR/"
cp -r "$REPO_DIR/nats"             "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$REPO_DIR/scripts"          "$INSTALL_DIR/"

# Copy importer
if [[ -f "$REPO_DIR/scripts/import_threat_intel.py" ]]; then
    cp "$REPO_DIR/scripts/import_threat_intel.py" "$INSTALL_DIR/scripts/"
    info "Threat intel importer installed"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/cyberwall_daemon.py"
info "Application files installed to $INSTALL_DIR"

# ── Install config ────────────────────────────────────────────────────────────
section "Installing configuration"

CONFIG_FILE="$CONFIG_DIR/cyberwall.yaml"

if [[ -f "$CONFIG_FILE" ]]; then
    warn "Config exists at $CONFIG_FILE — not overwriting"
    warn "To reset: cp $INSTALL_DIR/cyberwall/configs/cyberwall.example.yaml $CONFIG_FILE"
else
    # Generate standalone config
    cat > "$CONFIG_FILE" << YAML
# Sorabbyngo Cyberwall — Production Config
# Generated by installer: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Mode: $MODE

firewall:
  default_input:   drop
  default_forward: drop
  default_output:  accept
  interface:       $(ip route get 1.1.1.1 2>/dev/null | awk '/dev/{print $5}' | head -1 || echo "eth0")
  allowed_inbound_ports: [22, 80, 443, 8080, 8443]
  rate_limit:
    ssh:  { limit: "5/minute",    burst: 10   }
    http: { limit: "100/minute",  burst: 200  }
    nats: { limit: "1000/minute", burst: 2000 }
  blocked_ips: []

malware:
  watch_paths:
    - /etc
    - /bin
    - /sbin
    - /usr/bin
    - /usr/sbin
    - /lib/modules
    - /opt/sorabbyngo
    - /var/lib/sorabbyngo
  quarantine_path:        $DATA_DIR/quarantine
  scan_interval_seconds:  30
  auto_quarantine_level:  HIGH

response:
  auto_block_level:      HIGH
  auto_quarantine_level: CRITICAL
  alert_level:           LOW
  notify_sentinel:       $([ "$MODE" == "full" ] && echo "true" || echo "false")
  notify_cml:            false

ai:
  enabled:       $([ "$MODE" == "full" ] && echo "true" || echo "false")
  model:         phi4-mini
  ollama_url:    http://localhost:11434/api/generate
  analyze_level: MEDIUM

nats:
  url: nats://localhost:4222

signatures:
  db_path: $DATA_DIR/signatures/signatures.db
YAML
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    info "Config written to $CONFIG_FILE"
fi

# ── Threat intel ──────────────────────────────────────────────────────────────
if [[ "$SKIP_INTEL" == "false" ]]; then
    section "Importing threat intelligence"
    DB_PATH="$DATA_DIR/signatures/signatures.db"

    $PYTHON "$INSTALL_DIR/scripts/import_threat_intel.py" \
        --africa --seeds --whitelist \
        --db "$DB_PATH" 2>&1 | grep -E "\[INFO\]|Imported|Total"

    # Try bulk CSV (needs network)
    if $PYTHON "$INSTALL_DIR/scripts/import_threat_intel.py" \
        --bulk-csv --db "$DB_PATH" --limit 2000 2>&1 | grep -E "\[INFO\]|Imported|error"; then
        true
    else
        warn "Bulk CSV import failed — using offline signatures only"
    fi

    chown "$SERVICE_USER:$SERVICE_USER" "$DB_PATH" 2>/dev/null || true
    SIG_COUNT=$($PYTHON -c "
import sqlite3
try:
    c = sqlite3.connect('$DB_PATH').execute('SELECT COUNT(*) FROM malware_hashes')
    print(c.fetchone()[0])
except: print(0)
" 2>/dev/null || echo "0")
    info "Threat signatures loaded: $SIG_COUNT"
fi

# ── NATS (full mode) ──────────────────────────────────────────────────────────
if [[ "$MODE" == "full" ]]; then
    section "Setting up NATS"
    if command -v nats-server &>/dev/null; then
        cat > /etc/systemd/system/nats.service << 'NATSSVC'
[Unit]
Description=NATS Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nats-server -p 4222
Restart=on-failure

[Install]
WantedBy=multi-user.target
NATSSVC
        systemctl enable nats --now 2>/dev/null || true
        info "NATS server enabled"
    else
        warn "nats-server not found — sentinel bridge will run in log-only mode"
    fi
fi

# ── Systemd service ───────────────────────────────────────────────────────────
if [[ "$SKIP_SERVICE" == "false" ]]; then
    section "Installing systemd service"

    EXEC_FLAGS="--config $CONFIG_FILE"
    [[ "$MONITOR_ONLY" == "true" ]] && EXEC_FLAGS="$EXEC_FLAGS --monitor-only"

    cat > /etc/systemd/system/sorabbyngo-cyberwall.service << SVCFILE
[Unit]
Description=Sorabbyngo Cyberwall — AI-native Firewall and Malware Defence
Documentation=https://github.com/sorabbyngo-Labs/sorabbyngo-cyberwall
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/cyberwall_daemon.py $EXEC_FLAGS
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=60
StartLimitBurst=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberwall

RuntimeDirectory=sorabbyngo
StateDirectory=sorabbyngo
LogsDirectory=sorabbyngo

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$LOG_DIR $DATA_DIR /var/lib/sorabbyngo /tmp
PrivateTmp=yes
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=80%
WatchdogSec=60s

[Install]
WantedBy=multi-user.target
SVCFILE

    systemctl daemon-reload
    systemctl enable sorabbyngo-cyberwall
    info "Service installed and enabled"
    info "Start: sudo systemctl start sorabbyngo-cyberwall"
    info "Logs:  sudo journalctl -u sorabbyngo-cyberwall -f"
fi

# ── CLI symlink ───────────────────────────────────────────────────────────────
section "Installing CLI tools"

cat > /usr/local/bin/cyberwall << CWCLI
#!/bin/bash
# Sorabbyngo Cyberwall CLI wrapper
INSTALL_DIR="$INSTALL_DIR"
case "\$1" in
    start)   systemctl start sorabbyngo-cyberwall ;;
    stop)    systemctl stop sorabbyngo-cyberwall ;;
    restart) systemctl restart sorabbyngo-cyberwall ;;
    status)  systemctl status sorabbyngo-cyberwall ;;
    logs)    journalctl -u sorabbyngo-cyberwall -f ;;
    reload)  systemctl kill -s HUP sorabbyngo-cyberwall ;;
    test)    cd \$INSTALL_DIR && python3 -m tests.simulation.detection_harness --mock ;;
    intel)   python3 \$INSTALL_DIR/scripts/import_threat_intel.py \${@:2} ;;
    monitor) python3 \$INSTALL_DIR/cyberwall_daemon.py --monitor-only --no-root-checks --config $CONFIG_FILE ;;
    version) python3 -c "import cyberwall; print('Sorabbyngo Cyberwall v2')" ;;
    *)
        echo "Sorabbyngo Cyberwall CLI"
        echo "Usage: cyberwall <command>"
        echo ""
        echo "Commands:"
        echo "  start    — start the daemon"
        echo "  stop     — stop the daemon"
        echo "  restart  — restart the daemon"
        echo "  status   — show service status"
        echo "  logs     — follow logs"
        echo "  reload   — hot-reload policy (no restart)"
        echo "  test     — run detection harness"
        echo "  intel    — import threat intelligence"
        echo "  monitor  — run in monitor-only mode (no root needed)"
        echo "  version  — show version"
        ;;
esac
CWCLI

chmod +x /usr/local/bin/cyberwall
info "CLI: 'cyberwall' command available system-wide"

# ── Verify installation ───────────────────────────────────────────────────────
section "Verifying installation"

# Test Python imports
if $PYTHON -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from cyberwall.core.event_bus import EventBus
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.malware.deep_scanner import DeepScanner
from cyberwall.firewall.engine import FirewallEngine
print('imports OK')
" 2>/dev/null; then
    info "Python imports verified"
else
    error "Import check failed — check $INSTALL_DIR"
fi

# Test config parse
if $PYTHON -c "
import sys, yaml
sys.path.insert(0, '$INSTALL_DIR')
from cyberwall.core.policy_engine import PolicyEngine
p = PolicyEngine('$CONFIG_FILE')
print('config OK')
" 2>/dev/null; then
    info "Config verified"
else
    warn "Config check failed — check $CONFIG_FILE"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗"
echo -e "║           Cyberwall Installation Complete                ║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Install dir  : $INSTALL_DIR"
echo "  Config       : $CONFIG_FILE"
echo "  Logs         : $LOG_DIR"
echo "  Data         : $DATA_DIR"
echo "  Mode         : $MODE"
echo "  Monitor only : $MONITOR_ONLY"
echo ""
echo -e "${BOLD}Next steps:${NC}"
if [[ "$MONITOR_ONLY" == "true" ]]; then
    echo "  cyberwall monitor          # run now (no root, no firewall rules)"
else
    echo "  sudo systemctl start sorabbyngo-cyberwall   # start daemon"
    echo "  cyberwall status                            # check status"
fi
echo "  cyberwall logs                              # follow logs"
echo "  cyberwall test                              # run detection harness"
echo "  cyberwall intel --bulk-csv                  # update threat intel"
echo ""
echo -e "  ${BLUE}Sorabbyngo Company · Kisii, Kenya · 2026${NC}"
echo -e "  ${BLUE}Rhythm of Digital Life${NC}"
echo ""
