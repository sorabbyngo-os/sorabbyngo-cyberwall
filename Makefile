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
