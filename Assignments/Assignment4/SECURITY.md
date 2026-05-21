# Security Design Document

## 1. Overview

This document describes the security design of the Multi-Source Intrusion Detection System (IDS). The system is designed to detect network intrusions by correlating evidence from multiple independent sources, minimizing false positives through structured alert scoring and multi-source verification.

## 2. Threat Model

### 2.1 Adversary Capabilities

The system assumes an adversary with **limited capabilities**:

- **Can perform**: Brute-force login attempts, port scanning (fast and slow), traffic replay, noise injection to evade detection
- **Can attempt**: Temporarily disabling a single sensor
- **Cannot**: Completely compromise the IDS host, modify IDS code, intercept IDS internal queues, or disable multiple sensors simultaneously

### 2.2 Attack Vectors

| Attack Vector | Description | Detection Strategy |
|---|---|---|
| Brute-Force Login | Repeated authentication failures | Rate-based threshold on failed logins per IP within time window |
| Port Scanning | Probing multiple ports to discover services | Counting distinct ports accessed per IP within sliding windows (fast: 30s, slow: 300s) |
| Noise Injection | Flooding with benign traffic to mask attacks | Anomaly detection using z-score deviation from rolling baseline |
| Replay Attack | Replaying captured legitimate traffic | Pattern correlation and source IP reputation tracking |
| Sensor Evasion | Disabling one monitoring channel | Graceful degradation — remaining sensor continues detection |

### 2.3 Assumptions

1. The IDS runs on a trusted host that the adversary cannot fully compromise
2. At least one sensor remains operational at all times
3. The system clock is reliable (for time-window correlation)
4. Internal communication (thread queues) is not interceptable

## 3. Core Security Invariant

**Critical alerts require multi-source corroboration.**

This is the fundamental security property of the system:

> A **Critical** severity alert is ONLY raised when:
> 1. Evidence from ≥2 independent sources (network sensor + host sensor) agrees within a time window, **OR**
> 2. A deterministic multi-step attack pattern is detected through rule correlation
>
> If only one sensor provides evidence, the maximum alert severity is **High**.

### Why This Matters

- **Reduces false positives**: A single noisy sensor cannot trigger the highest alert level
- **Increases confidence**: Multi-source agreement provides stronger evidence
- **Prevents attacker manipulation**: An attacker who compromises one sensor cannot forge Critical alerts

### Implementation

The security invariant is enforced in `correlation_engine.py`:

```python
def _emit_alert(self, ..., sources: set, ...):
    # CORE SECURITY RULE: Cap at High if only 1 source
    if len(sources) < 2 and severity == config.SEVERITY_CRITICAL:
        severity = config.SEVERITY_HIGH
```

## 4. Defense-in-Depth Layers

### Layer 1: Event Schema Validation

All events must conform to a strict JSON schema (`event_schema.py`). Malformed events are rejected before entering the pipeline:

```python
def validate(self) -> bool:
    # Validates source, event_type, severity, tags, etc.
    # Raises ValueError if any field is invalid
```

This prevents:
- Injection of events with invalid sources
- Malformed data crashing downstream components
- Type confusion attacks

### Layer 2: Rule-Based Detection (6 Rules)

Deterministic rules detect known attack patterns:

1. **Brute-Force Login**: ≥5 failed logins from same IP within 60s
2. **Fast Port Scan**: ≥10 distinct ports from same IP within 30s
3. **Slow Port Scan**: ≥15 distinct ports from same IP within 300s
4. **Login After Scan**: Port scan followed by successful login (multi-source)
5. **Brute-Force Then Success**: Failed logins followed by success (multi-source)
6. **Suspicious Process After Login**: Login followed by suspicious process execution

### Layer 3: Statistical Anomaly Detection

Z-score based detection identifies deviations from normal behavior:

```
z_score = (current_value - rolling_mean) / (rolling_std + ε)
```

Monitored features:
- Failed login frequency per IP
- Number of unique ports accessed per IP
- Connection rate per IP

Alerts when z-score > 3.0 (configurable).

### Layer 4: Alert Management

- **Deduplication**: Same alert type + source IP suppressed within 60s cooldown
- **Rate limiting**: Maximum 50 alerts per minute prevents alert flooding
- **Severity hierarchy**: Info → Low → Medium → High → Critical

## 5. Scoring Model

Aggregate threat scores quantify risk per IP:

```
score(IP, time_window) = Σ weight(event_severity) for all events in window
```

Severity weights:
| Severity | Weight |
|----------|--------|
| Info | 0 |
| Low | 1 |
| Medium | 3 |
| High | 5 |
| Critical | 10 |

## 6. Robustness Design

### 6.1 Sensor Failure Handling

The system continues operating when a sensor fails:
- Remaining sensor generates events normally
- Correlation engine notes degraded mode
- Alert severity automatically capped at High (single source)
- No crashes or deadlocks when sensor stops

### 6.2 Noise Resilience

- Rolling statistics adapt to traffic patterns over time
- Rule-based detectors use strict thresholds to avoid benign traffic false positives
- Deduplication prevents alert storms from noisy periods

### 6.3 Resource Protection

- Event buffers are capped at 10,000 events per IP (oldest evicted)
- Alert rate limited to 50/minute
- Sliding windows automatically expire old events

### 6.4 Edge Cases Handled

| Edge Case | Handling |
|---|---|
| Zero traffic | Anomaly detector uses epsilon to prevent division by zero |
| Single-source evidence | Severity capped at High |
| Burst of benign traffic | Thresholds require specific attack patterns, not just volume |
| Overlapping attacks | Each IP tracked independently |
| Incomplete events | Schema validation rejects malformed events |
| Clock drift | Epoch timestamps used for consistent time comparison |

## 7. Communication Security

All components communicate through **in-process thread-safe queues** (Python `queue.Queue`):

- No network communication between IDS components
- No serialization/deserialization for inter-component messaging
- No risk of man-in-the-middle between components
- Thread safety guaranteed by Python's GIL and Queue implementation

## 8. Audit Trail

The system maintains a complete audit trail:

- **`host_events.log`**: All host-level events in JSON format
- **`alerts.json`**: All generated alerts with full metadata
- **`results/`**: Experiment metrics and analysis

All entries include timestamps, event IDs, and source tracing for forensic analysis.

## 9. Limitations

1. **Single-machine scope**: Not designed for distributed deployment
2. **No encrypted traffic inspection**: Operates on flow metadata only
3. **No persistent state**: State resets on restart (appropriate for this assignment)
4. **Rule-based detection bias**: Known attack patterns only; zero-day detection relies on anomaly detector
5. **Synthetic data**: Tested against simulated attacks, not real-world traffic

## 10. Testing Strategy

Security properties are verified through:

1. **Unit tests**: Each detector tested in isolation
2. **Integration tests**: Full pipeline tested with all attack scenarios
3. **Edge case tests**: Single-source cap, sensor failure, noise resilience
4. **Automated experiments**: All 5 attack scenarios with metrics computation
