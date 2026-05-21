"""
test_alert_manager.py — Tests for the Alert Manager.
"""

import sys
import os
import time
import unittest
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from event_schema import Event
from alert_manager import AlertManager, Alert


class TestAlertDeduplication(unittest.TestCase):
    """Test deduplication and cooldown logic."""

    def setUp(self):
        self.alert_queue = Queue()
        self.manager = AlertManager(self.alert_queue)
        self.manager.start()
        time.sleep(0.5)

    def tearDown(self):
        self.manager.stop()
        time.sleep(0.5)

    def test_duplicate_suppression(self):
        """Same alert type + IP within cooldown should be suppressed."""
        event1 = Event(
            source=config.SOURCE_CORRELATION,
            event_type="brute_force_login",
            severity=config.SEVERITY_HIGH,
            src_ip="10.0.0.99",
        )
        event1.description = "Test alert 1"
        event1.contributing_sources = {config.SOURCE_HOST}

        event2 = Event(
            source=config.SOURCE_CORRELATION,
            event_type="brute_force_login",
            severity=config.SEVERITY_HIGH,
            src_ip="10.0.0.99",
        )
        event2.description = "Test alert 2"
        event2.contributing_sources = {config.SOURCE_HOST}

        self.alert_queue.put(event1)
        time.sleep(0.5)
        self.alert_queue.put(event2)
        time.sleep(1)

        # Only 1 alert should be stored (second is duplicate)
        alerts = self.manager.get_alerts()
        self.assertEqual(
            len(alerts), 1,
            f"Expected 1 alert (dedup), got {len(alerts)}"
        )

    def test_different_ips_not_deduplicated(self):
        """Different IPs should NOT be deduplicated."""
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            event = Event(
                source=config.SOURCE_CORRELATION,
                event_type="brute_force_login",
                severity=config.SEVERITY_HIGH,
                src_ip=ip,
            )
            event.description = f"Alert from {ip}"
            event.contributing_sources = {config.SOURCE_HOST}
            self.alert_queue.put(event)
            time.sleep(0.3)

        time.sleep(1)
        alerts = self.manager.get_alerts()
        self.assertEqual(len(alerts), 3, f"Expected 3 alerts, got {len(alerts)}")

    def test_different_types_not_deduplicated(self):
        """Different alert types from same IP should NOT be deduplicated."""
        for alert_type in ["brute_force_login", "fast_port_scan", "replay"]:
            event = Event(
                source=config.SOURCE_CORRELATION,
                event_type=alert_type,
                severity=config.SEVERITY_HIGH,
                src_ip="10.0.0.99",
            )
            event.description = f"Alert type {alert_type}"
            event.contributing_sources = {config.SOURCE_HOST}
            self.alert_queue.put(event)
            time.sleep(0.3)

        time.sleep(1)
        alerts = self.manager.get_alerts()
        self.assertEqual(len(alerts), 3, f"Expected 3 alerts, got {len(alerts)}")


class TestAlertSeverityFiltering(unittest.TestCase):
    """Test alert filtering by severity."""

    def setUp(self):
        self.alert_queue = Queue()
        self.manager = AlertManager(self.alert_queue)
        self.manager.start()
        time.sleep(0.5)

    def tearDown(self):
        self.manager.stop()
        time.sleep(0.5)

    def test_filter_by_severity(self):
        """Should filter alerts by severity level."""
        severities = [
            config.SEVERITY_LOW,
            config.SEVERITY_MEDIUM,
            config.SEVERITY_HIGH,
        ]
        for i, sev in enumerate(severities):
            event = Event(
                source=config.SOURCE_CORRELATION,
                event_type=f"alert_{i}",
                severity=sev,
                src_ip=f"10.0.0.{i+1}",
            )
            event.description = f"Severity {sev}"
            event.contributing_sources = set()
            self.alert_queue.put(event)
            time.sleep(0.3)

        time.sleep(1)

        high_alerts = self.manager.get_alerts(severity=config.SEVERITY_HIGH)
        self.assertEqual(len(high_alerts), 1)

        medium_alerts = self.manager.get_alerts(severity=config.SEVERITY_MEDIUM)
        self.assertEqual(len(medium_alerts), 1)


class TestAlertSummary(unittest.TestCase):
    """Test alert summary generation."""

    def test_summary(self):
        alert_queue = Queue()
        manager = AlertManager(alert_queue)
        manager.start()
        time.sleep(0.5)

        for i in range(3):
            event = Event(
                source=config.SOURCE_CORRELATION,
                event_type=f"type_{i}",
                severity=config.SEVERITY_HIGH,
                src_ip=f"10.0.0.{i+1}",
            )
            event.description = "test"
            event.contributing_sources = set()
            alert_queue.put(event)
            time.sleep(0.3)

        time.sleep(1)
        summary = manager.get_alerts_summary()
        self.assertEqual(summary.get(config.SEVERITY_HIGH, 0), 3)

        manager.stop()

    def test_clear_alerts(self):
        alert_queue = Queue()
        manager = AlertManager(alert_queue)
        manager.start()
        time.sleep(0.5)

        event = Event(
            source=config.SOURCE_CORRELATION,
            event_type="test",
            severity=config.SEVERITY_HIGH,
            src_ip="10.0.0.1",
        )
        event.description = "test"
        event.contributing_sources = set()
        alert_queue.put(event)
        time.sleep(1)

        self.assertEqual(manager.get_alert_count(), 1)
        manager.clear_alerts()
        self.assertEqual(manager.get_alert_count(), 0)

        manager.stop()


if __name__ == "__main__":
    unittest.main()
