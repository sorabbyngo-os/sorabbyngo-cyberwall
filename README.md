# sorabbyngo-build
> **SORABBYNGO OS** — Build system, architecture decisions, and engineering roadmap
> *Rhythm of Digital Life* · Sorabbyngo Labs · Kisii, Kenya

## What is this repo?
This repository contains the master architecture decisions, phase plans, build system, and engineering roadmap for SORABBYNGO OS.

## Structure
```
docs/
├── decisions/          # Architecture decision records (ADRs)
│   ├── ADR-001-boot-target.md
│   ├── ADR-002-novela-deployment.md
│   └── ADR-003-ai-offline-strategy.md
├── phases/             # Build phases
│   ├── PHASE-1-kernel.md
│   ├── PHASE-2-rootfs.md
│   ├── PHASE-3-init.md
│   ├── PHASE-4-ai-runtime.md
│   ├── PHASE-5-iso-builder.md
│   └── PHASE-6-installer.md
└── architecture/       # System architecture
    └── SYSTEM-OVERVIEW.md
```

## Phase Status
| Phase | Description | Status |
|---|---|---|
| 1 | Custom kernel (Linux 6.19.10) | ✅ Complete |
| 2 | Root filesystem (Buildroot) | 🔜 Next |
| 3 | Init system (systemd) | 🔜 Planned |
| 4 | AI runtime layer | 🔜 Planned |
| 5 | ISO/image builder | 🔜 Planned |
| 6 | Installer | 🔜 Planned |

## Core Architecture Decisions
- Boot → Graphical Chameha (TTY hidden fallback)
- Novela → Core runs on-device + optional remote backend
- AI → Offline-first, tiered intelligence (local → enhanced → cloud)

© 2026 Sorabbyngo Company. All rights reserved.

## OS Surfaces (ADR-004)

All OS surfaces share the Sorabbyngo AI Kernel as root base.

| OS Surface | Target | Key Requirement | Status |
|---|---|---|---|
| Sorabbyngo OS | Base / development | Current build target | 🔧 In development |
| Novela OS | Medical / clinical | PREEMPT_RT real-time | 🔜 Planned |
| Byngo OS | Consumer devices | Android compatibility | 🔜 Planned |
| Edge OS | IoT / drones / vehicles | Minimal footprint | 🔜 Planned |
| Sentinel OS | Cybersecurity ops | Hardened kernel | 🔜 Planned |
| Server OS | Infrastructure | High throughput | 🔜 Planned |

See [ADR-004](docs/decisions/ADR-004-kernel-ecosystem-strategy.md) for full rationale.

## OS Surfaces (ADR-004)

All OS surfaces share the Sorabbyngo AI Kernel as root base.

| OS Surface | Target | Key Requirement | Status |
|---|---|---|---|
| Sorabbyngo OS | Base / development | Current build target | 🔧 In development |
| Novela OS | Medical / clinical | PREEMPT_RT real-time | 🔜 Planned |
| Byngo OS | Consumer devices | Android compatibility | 🔜 Planned |
| Edge OS | IoT / drones / vehicles | Minimal footprint | 🔜 Planned |
| Sentinel OS | Cybersecurity ops | Hardened kernel | 🔜 Planned |
| Server OS | Infrastructure | High throughput | 🔜 Planned |

See [ADR-004](docs/decisions/ADR-004-kernel-ecosystem-strategy.md) for full rationale.
