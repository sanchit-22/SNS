"""
test_integration.py — Integration tests for the full IDS pipeline.
"""

import sys
import os
import time
import unittest
from queue import Queue
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from event_schema import Event, create_network_event, create_login_event, create_process_event
from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from attack_simulator import AttackSimulator
from metrics import MetricsCollector


class TestFullPipeline(unittest.TestCase):
    """Test the complete IDS pipeline with attack simulator."""

    def setUp(self):
        self.event_queue = Queue()
        self.alert_queue = Queue()

        self.net_enabled = threading.Event()
        self.net_enabled.set()
        self.host_enabled = threading.Event()
        self.host_enabled.set()

        self.network_sensor = NetworkSensor(self.event_queue, self.net_enabled)
        self.host_sensor = HostSensor(self.event_queue, self.host_enabled)
        self.correlation_engine = CorrelationEngine(self.event_queue, self.alert_queue)
        self.alert_manager = AlertManager(self.alert_queue)

        self.alert_manager.start()
        self.correlation_engine.start()
        self.host_sensor.start()

        self.simulator = AttackSimulator(
            network_sensor=self.network_sensor,
            host_sensor=self.host_sensor,
        )

    def tearDown(self):
        self.network_sensor.stop()
        self.host_sensor.stop()
        self.correlation_engine.stop()
        self.alert_manager.stop()
        time.sleep(1)
        # Clean up log files
        for f in [config.HOST_LOG_FILE, config.ALERT_LOG_FILE]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass

    def test_brute_force_generates_alerts(self):
        """Full pipeline: brute-force attack should generate alerts."""
        self.simulator.attack_brute_force_login(
            attacker_ip="10.0.0.99",
            num_attempts=10,
            delay=0.05,
            succeed_at_end=True,
        )
        time.sleep(3)

        alerts = self.alert_manager.get_alerts()
        self.assertGreater(
            len(alerts), 0,
            "No alerts generated for brute-force attack"
        )

    def test_port_scan_generates_alerts(self):
        """Full pipeline: port scan should generate alerts."""
        self.simulator.attack_port_scan(
            attacker_ip="10.0.0.88",
            num_ports=20,
            delay=0.02,
            scan_type="fast",
        )
        time.sleep(3)

        alerts = self.alert_manager.get_alerts()
        self.assertGreater(len(alerts), 0, "No alerts for port scan")

    def test_benign_traffic_no_critical_alerts(self):
        """Benign traffic should not generate Critical alerts."""
        self.simulator.generate_benign_traffic(duration=5.0, rate=5.0)
        time.sleep(3)

        alerts = self.alert_manager.get_alerts()
        critical = [a for a in alerts if a.severity == config.SEVERITY_CRITICAL]
        self.assertEqual(
            len(critical), 0,
            f"Critical alerts from benign traffic: {[a.description for a in critical]}"
        )

    def test_sensor_failure_graceful(self):
        """System should not crash when a sensor is disabled."""
        self.network_sensor.disable()

        # Should still work with host sensor
        self.simulator.attack_brute_force_login(
            attacker_ip="10.0.0.55",
            num_attempts=10,
            delay=0.05,
            succeed_at_end=False,
        )
        time.sleep(3)

        # Should have host-based alerts
        alerts = self.alert_manager.get_alerts()
        self.assertGreater(len(alerts), 0, "No alerts with network sensor disabled")

        # Should NOT have Critical alerts (only host sensor)
        critical = [a for a in alerts if a.severity == config.SEVERITY_CRITICAL]
        self.assertEqual(
            len(critical), 0,
            "Critical alert with only one sensor active"
        )

        self.network_sensor.enable()

    def test_multi_step_attack_critical(self):
        """Multi-step attack should generate Critical alerts."""
        self.simulator.attack_multi_step(attacker_ip="10.0.0.42")
        time.sleep(5)

        alerts = self.alert_manager.get_alerts()
        self.assertGreater(len(alerts), 0, "No alerts for multi-step attack")

        # Should have at least one multi-source or critical alert
        high_or_critical = [
            a for a in alerts
            if a.severity in (config.SEVERITY_HIGH, config.SEVERITY_CRITICAL)
        ]
        self.assertGreater(
            len(high_or_critical), 0,
            "No High/Critical alerts for multi-step attack"
        )


class TestMetricsComputation(unittest.TestCase):
    """Test metrics computation against ground truth."""

    def test_perfect_detection(self):
        """Test metrics with perfect detection (all malicious detected)."""
        collector = MetricsCollector()
        collector.start_experiment()
        time.sleep(0.1)
        collector.end_experiment()

        # Create ground truth: 2 malicious IPs, 3 benign IPs
        ground_truth = [
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="10.0.0.1"), True),
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="10.0.0.2"), True),
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="192.168.1.1"), False),
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="192.168.1.2"), False),
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="192.168.1.3"), False),
        ]

        # Alerts match exactly the malicious IPs
        from alert_manager import Alert
        alerts = [
            Alert(Event(source=config.SOURCE_CORRELATION, event_type="test",
                        severity=config.SEVERITY_HIGH, src_ip="10.0.0.1")),
            Alert(Event(source=config.SOURCE_CORRELATION, event_type="test",
                        severity=config.SEVERITY_HIGH, src_ip="10.0.0.2")),
        ]

        metrics = collector.compute_metrics(alerts, ground_truth)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1_score"], 1.0)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)

    def test_false_positive(self):
        """Test metrics with false positives."""
        collector = MetricsCollector()
        collector.start_experiment()
        time.sleep(0.1)
        collector.end_experiment()

        ground_truth = [
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="10.0.0.1"), True),
            (Event(source=config.SOURCE_HOST, event_type=config.EVENT_LOGIN_ATTEMPT,
                   src_ip="192.168.1.1"), False),
        ]

        from alert_manager import Alert
        alerts = [
            Alert(Event(source=config.SOURCE_CORRELATION, event_type="test",
                        severity=config.SEVERITY_HIGH, src_ip="10.0.0.1")),
            Alert(Event(source=config.SOURCE_CORRELATION, event_type="test",
                        severity=config.SEVERITY_HIGH, src_ip="192.168.1.1")),  # FP
        ]

        metrics = collector.compute_metrics(alerts, ground_truth)
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["precision"], 0.5)


if __name__ == "__main__":
    unittest.main()
