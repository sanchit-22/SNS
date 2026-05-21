"""
test_correlation.py — Tests for the Correlation Engine.
"""

import sys
import os
import time
import unittest
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from event_schema import Event, create_network_event, create_login_event, create_process_event
from correlation_engine import CorrelationEngine, RollingStats


class TestRollingStats(unittest.TestCase):
    """Test the RollingStats helper."""

    def test_basic_stats(self):
        stats = RollingStats(window_size=10)
        for v in [10, 10, 10, 10, 10]:
            stats.update(v)

        self.assertEqual(stats.mean, 10.0)
        self.assertEqual(stats.std, 0.0)
        self.assertEqual(stats.count, 5)

    def test_z_score(self):
        stats = RollingStats(window_size=10)
        for v in [10, 10, 10, 10, 10]:
            stats.update(v)

        # With all same values, std=0, z-score should be very high for outlier
        z = stats.z_score(100)
        self.assertGreater(z, config.ANOMALY_Z_THRESHOLD)

    def test_rolling_window(self):
        stats = RollingStats(window_size=3)
        for v in [1, 2, 3, 4, 5]:
            stats.update(v)

        self.assertEqual(stats.count, 3)
        self.assertEqual(stats.mean, 4.0)  # average of [3, 4, 5]

    def test_empty_stats(self):
        stats = RollingStats()
        self.assertEqual(stats.mean, 0.0)
        self.assertEqual(stats.std, 0.0)
        self.assertEqual(stats.count, 0)
        # z-score of 0 with empty stats
        z = stats.z_score(0)
        self.assertEqual(z, 0.0)


class TestCorrelationRules(unittest.TestCase):
    """Test individual detection rules."""

    def setUp(self):
        self.event_queue = Queue()
        self.alert_queue = Queue()
        self.engine = CorrelationEngine(self.event_queue, self.alert_queue)

    def test_brute_force_detection(self):
        """Should detect brute-force when threshold is met."""
        attacker_ip = "10.0.0.99"

        for i in range(config.BRUTE_FORCE_THRESHOLD + 1):
            event = create_login_event(
                src_ip=attacker_ip,
                username="admin",
                success=False,
                is_malicious=True,
            )
            self.event_queue.put(event)

        # Start engine briefly
        self.engine.start()
        time.sleep(2)
        self.engine.stop()

        # Should have generated an alert
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())

        brute_force_alerts = [a for a in alerts if a.event_type == "brute_force_login"]
        self.assertGreater(len(brute_force_alerts), 0, "No brute-force alert generated")

    def test_brute_force_below_threshold(self):
        """Should NOT alert if below threshold."""
        attacker_ip = "10.0.0.99"

        for i in range(config.BRUTE_FORCE_THRESHOLD - 2):
            event = create_login_event(
                src_ip=attacker_ip,
                username="admin",
                success=False,
            )
            self.event_queue.put(event)

        self.engine.start()
        time.sleep(2)
        self.engine.stop()

        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())

        brute_force_alerts = [a for a in alerts if a.event_type == "brute_force_login"]
        self.assertEqual(len(brute_force_alerts), 0, "False positive brute-force alert")

    def test_fast_port_scan_detection(self):
        """Should detect fast port scan."""
        attacker_ip = "10.0.0.88"

        for port in range(config.FAST_SCAN_THRESHOLD + 2):
            event = create_network_event(
                src_ip=attacker_ip,
                dst_port=port + 1000,
                is_malicious=True,
            )
            self.event_queue.put(event)

        self.engine.start()
        time.sleep(2)
        self.engine.stop()

        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())

        scan_alerts = [a for a in alerts if a.event_type == "fast_port_scan"]
        self.assertGreater(len(scan_alerts), 0, "No port scan alert generated")

    def test_single_source_caps_at_high(self):
        """Critical alert should be downgraded to High with single source."""
        attacker_ip = "10.0.0.99"

        # Generate brute-force (host-only) followed by success
        for i in range(config.BRUTE_FORCE_THRESHOLD + 1):
            event = create_login_event(
                src_ip=attacker_ip,
                username="admin",
                success=False,
                is_malicious=True,
            )
            self.event_queue.put(event)

        # Success login (still host-only, no network events)
        success = create_login_event(
            src_ip=attacker_ip,
            username="admin",
            success=True,
            is_malicious=True,
        )
        self.event_queue.put(success)

        self.engine.start()
        time.sleep(2)
        self.engine.stop()

        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())

        # No alert should be Critical (only single host source)
        critical_alerts = [a for a in alerts if a.severity == config.SEVERITY_CRITICAL]
        self.assertEqual(
            len(critical_alerts), 0,
            f"Critical alert with single source! Alerts: {[(a.event_type, a.severity) for a in alerts]}"
        )

    def test_multi_source_allows_critical(self):
        """Critical alert should be allowed when ≥2 sources agree."""
        attacker_ip = "10.0.0.42"

        # Network events (port scan)
        for port in range(config.FAST_SCAN_THRESHOLD + 2):
            event = create_network_event(
                src_ip=attacker_ip,
                dst_port=port + 5000,
                is_malicious=True,
            )
            self.event_queue.put(event)

        # Host events (brute-force + success)
        for i in range(config.BRUTE_FORCE_THRESHOLD + 1):
            event = create_login_event(
                src_ip=attacker_ip,
                username="admin",
                success=False,
                is_malicious=True,
            )
            self.event_queue.put(event)

        # Successful login (triggers login_after_scan — multi-source)
        success = create_login_event(
            src_ip=attacker_ip,
            username="admin",
            success=True,
            is_malicious=True,
        )
        self.event_queue.put(success)

        self.engine.start()
        time.sleep(2)
        self.engine.stop()

        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())

        # Should have at least one Critical alert
        critical_alerts = [a for a in alerts if a.severity == config.SEVERITY_CRITICAL]
        self.assertGreater(
            len(critical_alerts), 0,
            f"No Critical alert with multi-source! Alerts: {[(a.event_type, a.severity) for a in alerts]}"
        )


class TestScoring(unittest.TestCase):
    """Test the scoring mechanism."""

    def test_score_computation(self):
        event_queue = Queue()
        alert_queue = Queue()
        engine = CorrelationEngine(event_queue, alert_queue)

        # Inject events directly into the engine's buffer
        ip = "10.0.0.1"
        events = [
            Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                  severity=config.SEVERITY_LOW, src_ip=ip),
            Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                  severity=config.SEVERITY_LOW, src_ip=ip),
            Event(source=config.SOURCE_NETWORK, event_type=config.EVENT_CONNECTION,
                  severity=config.SEVERITY_MEDIUM, src_ip=ip),
        ]

        for e in events:
            engine._events_by_ip[ip].append(e)

        score = engine.compute_score(ip, window=300)
        expected = 2 * config.SEVERITY_WEIGHTS[config.SEVERITY_LOW] + \
                   config.SEVERITY_WEIGHTS[config.SEVERITY_MEDIUM]
        self.assertEqual(score, expected)


if __name__ == "__main__":
    unittest.main()
