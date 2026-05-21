# Multi-Source Intrusion Detection System (IDS)

A lightweight, modular Intrusion Detection System that correlates evidence from multiple sources (network traffic and host logs) to detect attacks with high accuracy and minimal false positives.

## System Architecture

```
┌──────────────┐   ┌──────────────┐
│ Network      │   │ Host         │
│ Sensor       │   │ Sensor       │
└──────┬───────┘   └──────┬───────┘
       │   JSON events     │
       └────────┬──────────┘
                ▼
       ┌────────────────┐
       │  Correlation   │
       │    Engine      │
       └───────┬────────┘
               ▼
       ┌────────────────┐
       │  Alert         │
       │  Manager       │
       └───────┬────────┘
               ▼
         alerts.json / console

    ┌────────────────────┐
    │  Attack Simulator  │
    └────────────────────┘
```

## Requirements & Setup

- Python 3.8+
- No external heavy IDS frameworks (Snort/Suricata) are required.

To install the necessary testing and terminal styling libraries, run:

```bash
pip install pytest colorama psutil
```
*(Note: `psutil` is used for CPU/memory metrics, `colorama` for colorful terminal alerts, and `pytest` for the 45 automated unit/integration tests).*

## Quick Start

### 1. Run All Experiments

```bash
python run_experiments.py
```

This will:
1. Start the IDS pipeline (correlation engine, alert manager, sensors)
2. Run 7 attack scenarios sequentially
3. Generate benign baseline before each attack
4. Compute and display metrics (Precision, Recall, F1, latency)
5. Save results to `results/` directory

### 2. Interactive Mode

```bash
python main.py
```

Available commands:
- `benign` — Generate benign traffic
- `brute-force` — Launch brute-force login attack
- `port-scan` — Launch fast port scan
- `slow-scan` — Launch slow port scan
- `noise` — Noise injection attack
- `replay` — Replay attack
- `sensor-fail` — Sensor failure simulation
- `multi-step` — Multi-step attack
- `alerts` — Show all alerts
- `summary` — Alert summary
- `clear` — Clear alerts
- `quit` — Exit

### 3. Run Specific Attack

```bash
python main.py --attack brute-force
python main.py --attack port-scan
python main.py --attack multi-step
```

### 4. Run Tests

```bash
python -m pytest tests/ -v
```

Or individual test files:

```bash
python -m pytest tests/test_event_schema.py -v
python -m pytest tests/test_correlation.py -v
python -m pytest tests/test_alert_manager.py -v
python -m pytest tests/test_detectors.py -v
python -m pytest tests/test_integration.py -v
```

## Project Structure

```
assigne4/
├── main.py                 # Entry point (interactive/experiment/attack modes)
├── config.py               # All tuneable constants and thresholds
├── event_schema.py         # Unified JSON event schema + validation
├── network_sensor.py       # Network flow capture & event generation
├── host_sensor.py          # Host log monitoring & event generation
├── correlation_engine.py   # 6 rule-based + 1 anomaly detector
├── alert_manager.py        # Alert severity, dedup, cooldown, logging
├── attack_simulator.py     # 5+ attack scenarios + benign traffic
├── metrics.py              # Precision, Recall, F1, latency, resources
├── run_experiments.py      # Automated experiment runner
├── README.md               # This file
├── SECURITY.md             # Security design document
├── tests/
│   ├── test_event_schema.py
│   ├── test_correlation.py
│   ├── test_alert_manager.py
│   ├── test_detectors.py
│   └── test_integration.py
└── results/                # Experiment results (auto-generated)
```

## Detection Rules

| # | Rule | Trigger | Severity |
|---|------|---------|----------|
| 1 | Brute-Force Login | ≥5 failed logins, same IP, 60s | High |
| 2 | Fast Port Scan | ≥10 distinct ports, same IP, 30s | High |
| 3 | Slow Port Scan | ≥15 distinct ports, same IP, 300s | Medium |
| 4 | Login After Scan | Port scan + login success, same IP, 120s | Critical* |
| 5 | Brute-Force + Success | Failed logins + success, same IP, 120s | Critical* |
| 6 | Suspicious Process After Login | Login + suspicious process, same user, 60s | Critical* |

\* Critical only when evidence from ≥2 independent sources. Otherwise capped at High.

### Anomaly Detection

- Z-score based statistical detector
- Monitors: failed login rate, unique ports accessed, connection rate per IP
- Alert when z-score > 3.0 (configurable)

## Attack Scenarios

1. **Brute-Force Login** — 20+ failed SSH login attempts, then success
2. **Port Scan** — Fast (50 ports in seconds) and slow (20 ports over minutes)
3. **Noise Injection** — Heavy benign traffic with hidden malicious signals
4. **Replay Attack** — Replayed benign traffic from attacker IP
5. **Sensor Failure** — Network sensor disabled during attack

## Metrics

- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: Harmonic mean of Precision and Recall
- **False Positive Rate**: FP / (FP + TN)
- **False Negative Rate**: FN / (FN + TP)
- **Alert Latency**: Time from event injection to alert
- **CPU & Memory**: Via psutil (optional)

## Configuration

All thresholds are tuneable in `config.py`:

```python
BRUTE_FORCE_THRESHOLD = 5      # failed logins to trigger
FAST_SCAN_THRESHOLD = 10       # distinct ports for fast scan
ANOMALY_Z_THRESHOLD = 3.0      # z-score for anomaly detection
DEDUP_COOLDOWN_SECONDS = 60    # cooldown between same alerts
```
