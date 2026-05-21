"""
alert_manager.py — Alert Manager for the Multi-Source IDS.

Receives alert events from the correlation engine, assigns final severity,
applies deduplication and cooldown logic, and logs alerts.
"""

import threading
import time
import json
import os
import logging
from queue import Queue, Empty
from collections import defaultdict
from typing import List, Dict, Optional

import config
from event_schema import Event

logger = logging.getLogger("IDS.AlertManager")


class Alert:
    """Represents a finalized alert with metadata."""

    def __init__(self, event: Event, description: str = "", sources: Optional[set] = None):
        self.event = event
        self.alert_id = event.event_id
        self.alert_type = event.event_type
        self.severity = event.severity
        self.src_ip = event.src_ip
        self.username = event.username
        self.description = getattr(event, "description", description)
        self.sources = sources or getattr(event, "contributing_sources", set())
        self.timestamp = event.epoch
        self.tags = event.tags
        self.acknowledged = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "username": self.username,
            "description": self.description,
            "sources": list(self.sources),
            "timestamp": self.event.timestamp,
            "epoch": self.timestamp,
            "tags": self.tags,
            "acknowledged": self.acknowledged,
        }

    def __repr__(self):
        return (
            f"Alert(type={self.alert_type}, severity={self.severity}, "
            f"ip={self.src_ip}, desc={self.description[:60]})"
        )


class AlertManager:
    """
    Manages alert lifecycle: deduplication, cooldown, severity assignment,
    rate limiting, and persistent logging.
    """

    def __init__(self, alert_queue: Queue):
        """
        Args:
            alert_queue: Queue of alert events from the CorrelationEngine.
        """
        self.alert_queue = alert_queue
        self._stop_event = threading.Event()
        self._thread = None

        # Deduplication: (alert_type, src_ip) -> last alert epoch
        self._dedup_map: Dict[tuple, float] = {}
        self._dedup_lock = threading.Lock()

        # All finalized alerts (for metrics)
        self.alerts: List[Alert] = []
        self._alerts_lock = threading.Lock()

        # Rate limiting counter
        self._alerts_this_minute = 0
        self._minute_start = time.time()

        # Alert log file
        self._log_file = config.ALERT_LOG_FILE

    def start(self):
        """Start the alert manager."""
        logger.info("Alert Manager starting...")
        # Clear previous alert log
        with open(self._log_file, "w") as f:
            f.write("")
        self._thread = threading.Thread(target=self._process_alerts, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the alert manager."""
        logger.info("Alert Manager stopping...")
        self._stop_event.set()

    def _process_alerts(self):
        """Main alert processing loop."""
        while not self._stop_event.is_set():
            try:
                event = self.alert_queue.get(timeout=0.5)
            except Empty:
                continue

            alert = Alert(event)

            # Apply deduplication
            if self._is_duplicate(alert):
                logger.debug(f"Suppressed duplicate alert: {alert.alert_type} from {alert.src_ip}")
                continue

            # Apply rate limiting
            if not self._rate_limit_ok():
                logger.warning("Alert rate limit exceeded, dropping alert")
                continue

            # Finalize and store
            self._finalize_alert(alert)

    def _is_duplicate(self, alert: Alert) -> bool:
        """Check if this alert is a duplicate based on cooldown window."""
        key = (alert.alert_type, alert.src_ip)
        now = time.time()

        with self._dedup_lock:
            last_time = self._dedup_map.get(key, 0)
            if now - last_time < config.DEDUP_COOLDOWN_SECONDS:
                return True
            self._dedup_map[key] = now
            return False

    def _rate_limit_ok(self) -> bool:
        """Check if we're within the rate limit."""
        now = time.time()
        if now - self._minute_start >= 60:
            self._alerts_this_minute = 0
            self._minute_start = now

        self._alerts_this_minute += 1
        return self._alerts_this_minute <= config.MAX_ALERTS_PER_MINUTE

    def _finalize_alert(self, alert: Alert):
        """Store and log a finalized alert."""
        with self._alerts_lock:
            self.alerts.append(alert)

        # Log to file
        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except IOError as e:
            logger.error(f"Failed to write alert log: {e}")

        # Console output with severity-based formatting
        severity_icons = {
            config.SEVERITY_INFO: "ℹ️ ",
            config.SEVERITY_LOW: "🔵",
            config.SEVERITY_MEDIUM: "🟡",
            config.SEVERITY_HIGH: "🟠",
            config.SEVERITY_CRITICAL: "🔴",
        }
        icon = severity_icons.get(alert.severity, "⚪")
        color = config.SEVERITY_COLORS.get(alert.severity, config.Colors.ENDC)
        reset = config.Colors.ENDC
        print(
            f"\n{color}{icon} [{alert.severity.upper()}] {alert.alert_type}{reset}\n"
            f"   IP: {config.Colors.OKCYAN}{alert.src_ip}{reset} | User: {config.Colors.OKCYAN}{alert.username or 'N/A'}{reset}\n"
            f"   {config.Colors.BOLD}{alert.description}{reset}\n"
            f"   Sources: {', '.join(alert.sources) if alert.sources else 'unknown'}\n"
            f"   Tags: {', '.join(alert.tags)}"
        )

    def get_alerts(self, severity: Optional[str] = None) -> List[Alert]:
        """Get all alerts, optionally filtered by severity."""
        with self._alerts_lock:
            if severity:
                return [a for a in self.alerts if a.severity == severity]
            return list(self.alerts)

    def get_alert_count(self) -> int:
        """Get total number of finalized alerts."""
        with self._alerts_lock:
            return len(self.alerts)

    def clear_alerts(self):
        """Clear all stored alerts (for between experiments)."""
        with self._alerts_lock:
            self.alerts.clear()
        with self._dedup_lock:
            self._dedup_map.clear()
        self._alerts_this_minute = 0

    def get_alerts_summary(self) -> dict:
        """Get a summary of alerts by severity."""
        with self._alerts_lock:
            summary = defaultdict(int)
            for alert in self.alerts:
                summary[alert.severity] += 1
            return dict(summary)
