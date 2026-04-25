# Sorabbyngo Cyberwall — Dev Makefile

.PHONY: install test sim sim-all sim-files lint run run-monitor install-service

# ── Install ────────────────────────────────────────────────────────────────────
install:
	pip install -r requirements.txt --break-system-packages

# ── Tests ──────────────────────────────────────────────────────────────────────
test:
	pytest tests/unit/ -v

test-cov:
	pytest tests/unit/ -v --cov=cyberwall --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

# ── Simulation ─────────────────────────────────────────────────────────────────
sim:
	@echo "Usage: make sim SCENARIO=port_scan"
	python3 -m tests.simulation.attack_simulator --scenario $(SCENARIO)

sim-all:
	python3 -m tests.simulation.attack_simulator --scenario all

sim-list:
	python3 -m tests.simulation.attack_simulator --list

# ── Detection harness (sim + verify cyberwall catches it) ─────────────────────
harness:
	python3 -m tests.simulation.detection_harness --mock

harness-scenario:
	python3 -m tests.simulation.detection_harness --mock --scenario $(SCENARIO)

# ── Lint ───────────────────────────────────────────────────────────────────────
lint:
	python3 -m py_compile cyberwall/core/*.py cyberwall/firewall/*.py \
	    cyberwall/malware/*.py cyberwall/sentinel_bridge/*.py cyberwall/ai/*.py
	@echo "Syntax OK"

# ── Run ────────────────────────────────────────────────────────────────────────
run:
	sudo python3 cyberwall_daemon.py --config configs/cyberwall.yaml

run-monitor:
	python3 cyberwall_daemon.py --monitor-only --no-root-checks

run-dev:
	python3 cyberwall_daemon.py --monitor-only --no-root-checks \
	    --config configs/cyberwall.example.yaml

# ── Systemd ────────────────────────────────────────────────────────────────────
install-service:
	sudo cp scripts/sorabbyngo-cyberwall.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable sorabbyngo-cyberwall
	@echo "Service installed. Start with: sudo systemctl start sorabbyngo-cyberwall"

reload-policy:
	sudo systemctl kill -s HUP sorabbyngo-cyberwall

status:
	sudo systemctl status sorabbyngo-cyberwall
	sudo journalctl -u sorabbyngo-cyberwall -n 50 --no-pager

# ── Standalone packaging ───────────────────────────────────────────────────────
.PHONY: install-standalone install-full install-monitor verify uninstall

install-standalone:
	@echo "Installing Cyberwall (standalone mode)..."
	sudo bash scripts/install.sh --standalone

install-full:
	@echo "Installing Cyberwall (full mode with NATS)..."
	sudo bash scripts/install.sh --full

install-monitor:
	@echo "Installing Cyberwall (monitor-only, no firewall rules)..."
	sudo bash scripts/install.sh --standalone --monitor-only

verify:
	@echo "Verifying installation..."
	@python3 -c "import sys; sys.path.insert(0,'$(or $(INSTALL_DIR),/opt/sorabbyngo/cyberwall)'); \
	    from cyberwall.core.event_bus import EventBus; \
	    from cyberwall.core.policy_engine import PolicyEngine; \
	    print('✓ imports OK')"
	@python3 /usr/local/bin/../opt/sorabbyngo/cyberwall/scripts/import_threat_intel.py \
	    --africa --dry-run --db /tmp/verify_sigs.db 2>&1 | grep -E "Imported|Total"
	@echo "✓ Cyberwall installation verified"

uninstall:
	@echo "Removing Cyberwall..."
	-sudo systemctl stop sorabbyngo-cyberwall 2>/dev/null
	-sudo systemctl disable sorabbyngo-cyberwall 2>/dev/null
	-sudo rm -f /etc/systemd/system/sorabbyngo-cyberwall.service
	-sudo systemctl daemon-reload
	-sudo rm -rf /opt/sorabbyngo/cyberwall
	-sudo rm -f /usr/local/bin/cyberwall
	-sudo rm -f /etc/sorabbyngo/cyberwall.yaml
	@echo "Cyberwall removed. Data preserved in /var/lib/cyberwall"
	@echo "To also remove data: sudo rm -rf /var/lib/cyberwall /var/log/sorabbyngo"

# ── Threat intel ───────────────────────────────────────────────────────────────
import-intel:
	python3 scripts/import_threat_intel.py --africa --seeds --whitelist \
	    --bulk-csv --limit 5000 \
	    --db /var/lib/cyberwall/signatures/signatures.db

import-intel-offline:
	python3 scripts/import_threat_intel.py --africa --seeds --whitelist \
	    --db /var/lib/cyberwall/signatures/signatures.db
