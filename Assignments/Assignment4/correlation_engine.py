"""
correlation_engine.py — Correlation Engine for the Multi-Source IDS.

Combines events from network and host sensors, runs 6 rule-based detectors
and 1 statistical anomaly detector. Enforces the core security requirement:
Critical alerts only when evidence from ≥2 independent sources agrees.
"""

import threading
import time
import math
import logging
from queue import Queue, Empty
from collections import defaultdict
from typing import List, Dict, Tuple, Optional

import config
from event_schema import Event

logger = logging.getLogger("IDS.CorrelationEngine")


class RollingStats:
    """Maintains rolling mean and standard deviation for anomaly detection."""

    def __init__(self, window_size: int = config.ANOMALY_ROLLING_WINDOW):
        self.window_size = window_size
        self.values = []

    def update(self, value: float):
        self.values.append(value)
        if len(self.values) > self.window_size:
            self.values.pop(0)

    @property
    def mean(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def std(self) -> float:
        if len(self.values) < 2:
            return 0.0
        mu = self.mean
        variance = sum((x - mu) ** 2 for x in self.values) / len(self.values)
        return math.sqrt(variance)

    def z_score(self, value: float) -> float:
        """Compute z-score: z = (value - μ) / (σ + ε)"""
        return (value - self.mean) / (self.std + config.ANOMALY_EPSILON)

    @property
    def count(self) -> int:
        return len(self.values)


class CorrelationEngine:
    """
    Central detection engine. Consumes events from all sensors and runs
    detection rules + anomaly detection. Produces alert events.
    """

    def __init__(self, event_queue: Queue, alert_queue: Queue):
        """
        Args:
            event_queue: Incoming events from sensors.
            alert_queue: Outgoing alerts to the alert manager.
        """
        self.event_queue = event_queue
        self.alert_queue = alert_queue
        self._stop_event = threading.Event()
        self._thread = None

        # Event buffer keyed by source IP for rule-based detection
        self._events_by_ip: Dict[str, List[Event]] = defaultdict(list)
        # Events keyed by username for host-based correlation
        self._events_by_user: Dict[str, List[Event]] = defaultdict(list)
        self._lock = threading.Lock()

        # Rolling statistics for anomaly detection per IP
        self._login_fail_stats: Dict[str, RollingStats] = defaultdict(RollingStats)
        self._port_access_stats: Dict[str, RollingStats] = defaultdict(RollingStats)
        self._conn_rate_stats: Dict[str, RollingStats] = defaultdict(RollingStats)

        # Per-IP counters reset every stats window
        self._ip_login_fails: Dict[str, int] = defaultdict(int)
        self._ip_ports_accessed: Dict[str, set] = defaultdict(set)
        self._ip_conn_count: Dict[str, int] = defaultdict(int)

        # Last stats computation time
        self._last_stats_time = time.time()
        self._stats_interval = 10  # compute stats every 10 seconds

    def start(self):
        """Start the correlation engine."""
        logger.info("Correlation Engine starting...")
        self._thread = threading.Thread(target=self._process_events, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the correlation engine."""
        logger.info("Correlation Engine stopping...")
        self._stop_event.set()

    def _process_events(self):
        """Main event processing loop."""
        while not self._stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=0.5)
            except Empty:
                # Even with no new events, periodically run anomaly detection
                self._periodic_anomaly_check()
                continue

            with self._lock:
                # Store event in buffers
                if event.src_ip:
                    self._events_by_ip[event.src_ip].append(event)
                    self._trim_buffer(self._events_by_ip[event.src_ip])
                if event.username:
                    self._events_by_user[event.username].append(event)
                    self._trim_buffer(self._events_by_user[event.username])

                # Update counters for anomaly detection
                self._update_counters(event)

                # Run all rule-based detectors
                self._run_rules(event)

                # Run anomaly detection periodically
                self._periodic_anomaly_check()

    def _trim_buffer(self, event_list: List[Event]):
        """Trim event buffer to max size, removing oldest events."""
        if len(event_list) > config.EVENT_BUFFER_MAX_SIZE:
            del event_list[: len(event_list) - config.EVENT_BUFFER_MAX_SIZE]

    def _update_counters(self, event: Event):
        """Update per-IP counters for anomaly detection."""
        ip = event.src_ip
        if not ip:
            return

        if event.event_type == config.EVENT_LOGIN_ATTEMPT and event.status == "failure":
            self._ip_login_fails[ip] += 1

        if event.event_type == config.EVENT_CONNECTION:
            self._ip_ports_accessed[ip].add(event.dst_port)
            self._ip_conn_count[ip] += 1

    def _periodic_anomaly_check(self):
        """Run anomaly detection on accumulated counters."""
        now = time.time()
        if now - self._last_stats_time < self._stats_interval:
            return
        self._last_stats_time = now

        for ip in list(self._ip_login_fails.keys()):
            count = self._ip_login_fails[ip]
            stats = self._login_fail_stats[ip]
            stats.update(count)

            if stats.count >= 5:  # need enough data points
                z = stats.z_score(count)
                if z > config.ANOMALY_Z_THRESHOLD:
                    self._emit_alert(
                        alert_type="anomaly_login_failure_rate",
                        severity=config.SEVERITY_HIGH,
                        src_ip=ip,
                        description=f"Anomalous login failure rate: {count} failures "
                                    f"(z-score={z:.2f})",
                        tags=["anomaly", "login_failure"],
                        sources={config.SOURCE_HOST},
                    )

        for ip in list(self._ip_ports_accessed.keys()):
            port_count = len(self._ip_ports_accessed[ip])
            stats = self._port_access_stats[ip]
            stats.update(port_count)

            if stats.count >= 5:
                z = stats.z_score(port_count)
                if z > config.ANOMALY_Z_THRESHOLD:
                    self._emit_alert(
                        alert_type="anomaly_port_access_rate",
                        severity=config.SEVERITY_HIGH,
                        src_ip=ip,
                        description=f"Anomalous port access pattern: {port_count} ports "
                                    f"(z-score={z:.2f})",
                        tags=["anomaly", "port_scan"],
                        sources={config.SOURCE_NETWORK},
                    )

        for ip in list(self._ip_conn_count.keys()):
            count = self._ip_conn_count[ip]
            stats = self._conn_rate_stats[ip]
            stats.update(count)

            if stats.count >= 5:
                z = stats.z_score(count)
                if z > config.ANOMALY_Z_THRESHOLD:
                    self._emit_alert(
                        alert_type="anomaly_connection_rate",
                        severity=config.SEVERITY_HIGH,
                        src_ip=ip,
                        description=f"Anomalous connection rate: {count} connections "
                                    f"(z-score={z:.2f})",
                        tags=["anomaly", "traffic_burst"],
                        sources={config.SOURCE_NETWORK},
                    )

        # Reset counters for next interval
        self._ip_login_fails.clear()
        self._ip_ports_accessed.clear()
        self._ip_conn_count.clear()

    # ─── Rule-Based Detectors ─────────────────────────────────────────

    def _run_rules(self, event: Event):
        """Run all 6 rule-based detectors against the current event."""
        self._rule_brute_force_login(event)
        self._rule_fast_port_scan(event)
        self._rule_slow_port_scan(event)
        self._rule_login_after_scan(event)
        self._rule_brute_force_then_success(event)
        self._rule_suspicious_process_after_login(event)

    def _get_recent_events(
        self, ip: str, window_seconds: float, event_type: Optional[str] = None
    ) -> List[Event]:
        """Get events from a specific IP within a time window."""
        now = time.time()
        cutoff = now - window_seconds
        events = self._events_by_ip.get(ip, [])
        result = [
            e for e in events
            if e.epoch >= cutoff and (event_type is None or e.event_type == event_type)
        ]
        return result

    def _get_recent_user_events(
        self, username: str, window_seconds: float, event_type: Optional[str] = None
    ) -> List[Event]:
        """Get events from a specific user within a time window."""
        now = time.time()
        cutoff = now - window_seconds
        events = self._events_by_user.get(username, [])
        return [
            e for e in events
            if e.epoch >= cutoff and (event_type is None or e.event_type == event_type)
        ]

    def _get_sources_in_events(self, events: List[Event]) -> set:
        """Get unique sources present in a list of events."""
        return {e.source for e in events}

    # ── Rule 1: Brute-Force Login Detection ──
    def _rule_brute_force_login(self, event: Event):
        """Detect brute-force login attempts: ≥ threshold failed logins in window."""
        if event.event_type != config.EVENT_LOGIN_ATTEMPT or event.status != "failure":
            return

        ip = event.src_ip
        failed_logins = self._get_recent_events(
            ip, config.BRUTE_FORCE_WINDOW, config.EVENT_LOGIN_ATTEMPT
        )
        failed_logins = [e for e in failed_logins if e.status == "failure"]

        if len(failed_logins) >= config.BRUTE_FORCE_THRESHOLD:
            self._emit_alert(
                alert_type="brute_force_login",
                severity=config.SEVERITY_HIGH,
                src_ip=ip,
                description=f"Brute-force login detected: {len(failed_logins)} failed "
                            f"attempts in {config.BRUTE_FORCE_WINDOW}s",
                tags=["brute_force", "login"],
                sources={config.SOURCE_HOST},
                username=event.username,
            )

    # ── Rule 2: Fast Port Scan Detection ──
    def _rule_fast_port_scan(self, event: Event):
        """Detect fast port scan: ≥ threshold distinct ports in short window."""
        if event.event_type != config.EVENT_CONNECTION:
            return

        ip = event.src_ip
        connections = self._get_recent_events(
            ip, config.FAST_SCAN_WINDOW, config.EVENT_CONNECTION
        )
        unique_ports = {e.dst_port for e in connections}

        if len(unique_ports) >= config.FAST_SCAN_THRESHOLD:
            self._emit_alert(
                alert_type="fast_port_scan",
                severity=config.SEVERITY_HIGH,
                src_ip=ip,
                description=f"Fast port scan detected: {len(unique_ports)} ports in "
                            f"{config.FAST_SCAN_WINDOW}s",
                tags=["port_scan", "fast"],
                sources={config.SOURCE_NETWORK},
            )

    # ── Rule 3: Slow Port Scan Detection ──
    def _rule_slow_port_scan(self, event: Event):
        """Detect slow/stealth port scan: ≥ threshold ports in larger window."""
        if event.event_type != config.EVENT_CONNECTION:
            return

        ip = event.src_ip
        connections = self._get_recent_events(
            ip, config.SLOW_SCAN_WINDOW, config.EVENT_CONNECTION
        )
        unique_ports = {e.dst_port for e in connections}

        if len(unique_ports) >= config.SLOW_SCAN_THRESHOLD:
            # Only fire if didn't already fire as fast scan
            fast_connections = self._get_recent_events(
                ip, config.FAST_SCAN_WINDOW, config.EVENT_CONNECTION
            )
            fast_ports = {e.dst_port for e in fast_connections}
            if len(fast_ports) < config.FAST_SCAN_THRESHOLD:
                self._emit_alert(
                    alert_type="slow_port_scan",
                    severity=config.SEVERITY_MEDIUM,
                    src_ip=ip,
                    description=f"Slow port scan detected: {len(unique_ports)} ports in "
                                f"{config.SLOW_SCAN_WINDOW}s",
                    tags=["port_scan", "slow", "evasion"],
                    sources={config.SOURCE_NETWORK},
                )

    # ── Rule 4: Login After Port Scan (Multi-Source) ──
    def _rule_login_after_scan(self, event: Event):
        """
        Detect login success following a port scan from the same IP.
        This is a MULTI-SOURCE correlation → can trigger Critical.
        """
        if event.event_type != config.EVENT_LOGIN_SUCCESS:
            return

        ip = event.src_ip
        # Check if this IP had a port scan recently
        recent_events = self._get_recent_events(ip, config.LOGIN_AFTER_SCAN_WINDOW)
        scan_events = [e for e in recent_events if "port_scan" in e.tags or
                       e.event_type == config.EVENT_CONNECTION]
        host_events = [e for e in recent_events if e.source == config.SOURCE_HOST]
        net_events = [e for e in recent_events if e.source == config.SOURCE_NETWORK]

        unique_ports = {e.dst_port for e in scan_events if e.event_type == config.EVENT_CONNECTION}

        if len(unique_ports) >= config.FAST_SCAN_THRESHOLD and host_events and net_events:
            sources = {config.SOURCE_NETWORK, config.SOURCE_HOST}
            self._emit_alert(
                alert_type="login_after_scan",
                severity=config.SEVERITY_CRITICAL,
                src_ip=ip,
                description=f"Login success after port scan: {len(unique_ports)} ports "
                            f"scanned, then login as '{event.username}'",
                tags=["port_scan", "login", "multi_source", "lateral_movement"],
                sources=sources,
                username=event.username,
            )

    # ── Rule 5: Brute-Force Then Success (Multi-Source) ──
    def _rule_brute_force_then_success(self, event: Event):
        """
        Detect successful login following brute-force attempts.
        Multi-source if network events also present.
        """
        if event.event_type != config.EVENT_LOGIN_SUCCESS:
            return

        ip = event.src_ip
        recent_events = self._get_recent_events(ip, config.BRUTE_SUCCESS_WINDOW)
        failed_logins = [
            e for e in recent_events
            if e.event_type == config.EVENT_LOGIN_ATTEMPT and e.status == "failure"
        ]

        if len(failed_logins) >= config.BRUTE_FORCE_THRESHOLD:
            # Determine if multi-source
            all_recent = self._get_recent_events(ip, config.BRUTE_SUCCESS_WINDOW)
            sources = self._get_sources_in_events(all_recent)

            severity = config.SEVERITY_CRITICAL if len(sources) >= 2 else config.SEVERITY_HIGH

            self._emit_alert(
                alert_type="brute_force_then_success",
                severity=severity,
                src_ip=ip,
                description=f"Successful login after {len(failed_logins)} brute-force "
                            f"attempts as '{event.username}'",
                tags=["brute_force", "login_success", "credential_compromise"]
                     + (["multi_source"] if len(sources) >= 2 else []),
                sources=sources,
                username=event.username,
            )

    # ── Rule 6: Suspicious Process After Login (Multi-Source) ──
    def _rule_suspicious_process_after_login(self, event: Event):
        """
        Detect suspicious process execution shortly after a login.
        This is a host-only correlation but can be Critical if network
        events also exist for the same IP.
        """
        if event.event_type != config.EVENT_PROCESS_EXEC:
            return
        if "suspicious_process" not in event.tags:
            return

        username = event.username
        ip = event.src_ip

        # Check for recent login
        recent_user_events = self._get_recent_user_events(
            username, config.SUSPICIOUS_PROC_WINDOW, config.EVENT_LOGIN_SUCCESS
        )

        if recent_user_events:
            # Check if multi-source evidence exists
            all_ip_events = self._get_recent_events(ip, config.SUSPICIOUS_PROC_WINDOW)
            sources = self._get_sources_in_events(all_ip_events + [event])

            severity = config.SEVERITY_CRITICAL if len(sources) >= 2 else config.SEVERITY_HIGH

            self._emit_alert(
                alert_type="suspicious_process_after_login",
                severity=severity,
                src_ip=ip,
                description=f"Suspicious process '{event.process_name}' executed by "
                            f"'{username}' after recent login",
                tags=["process_exec", "post_exploitation"]
                     + (["multi_source"] if len(sources) >= 2 else []),
                sources=sources,
                username=username,
            )

    # ─── Alert Emission ───────────────────────────────────────────────

    def _emit_alert(
        self,
        alert_type: str,
        severity: str,
        src_ip: str,
        description: str,
        tags: list,
        sources: set,
        username: str = "",
    ):
        """
        Create and emit an alert event.
        Enforces the core security requirement: Critical only with ≥2 sources.
        """
        # CORE SECURITY RULE: Cap at High if only 1 source
        if len(sources) < 2 and severity == config.SEVERITY_CRITICAL:
            logger.info(
                f"Downgrading alert '{alert_type}' from Critical to High "
                f"(single source: {sources})"
            )
            severity = config.SEVERITY_HIGH

        alert_event = Event(
            source=config.SOURCE_CORRELATION,
            event_type=alert_type,
            severity=severity,
            src_ip=src_ip,
            username=username,
            tags=tags,
        )
        alert_event.description = description
        alert_event.contributing_sources = sources

        self.alert_queue.put(alert_event)
        logger.info(
            f"ALERT [{severity.upper()}] {alert_type}: {description} "
            f"(sources: {sources})"
        )

    def compute_score(self, ip: str, window: float = None) -> float:
        """
        Compute aggregate threat score for an IP.
        score(ip, t) = Σ w(event) for events in window.
        """
        window = window or config.CORRELATION_WINDOW
        events = self._get_recent_events(ip, window)
        score = sum(config.SEVERITY_WEIGHTS.get(e.severity, 0) for e in events)
        return score
