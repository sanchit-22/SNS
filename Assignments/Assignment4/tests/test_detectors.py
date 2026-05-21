"""
test_detectors.py — Tests for individual detectors in the Correlation Engine.
"""

import sys
import os
import time
import unittest
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from event_schema import Event, create_network_event, create_login_event, create_process_event
from correlation_engine import CorrelationEngine


class TestBruteForceDetector(unittest.TestCase):
    """Test brute-force login detector."""

    def test_exact_threshold(self):
        """Alert should fire at exactly the threshold."""
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        for i in range(config.BRUTE_FORCE_THRESHOLD):
            eq.put(create_login_event("10.0.0.1", "admin", False, True))
            time.sleep(0.05)

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())
        bf = [a for a in alerts if a.event_type == "brute_force_login"]
        self.assertGreater(len(bf), 0)

    def test_different_ips_independent(self):
        """Brute-force from different IPs should be tracked independently."""
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        # 3 attempts from each of 2 IPs (below threshold of 5)
        for ip in ["10.0.0.1", "10.0.0.2"]:
            for _ in range(3):
                eq.put(create_login_event(ip, "admin", False))
                time.sleep(0.05)

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())
        bf = [a for a in alerts if a.event_type == "brute_force_login"]
        self.assertEqual(len(bf), 0, "Should not fire — each IP below threshold")


class TestPortScanDetector(unittest.TestCase):
    """Test port scan detectors."""

    def test_fast_scan_detection(self):
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        for port in range(config.FAST_SCAN_THRESHOLD + 5):
            eq.put(create_network_event("10.0.0.88", port + 1000))
            time.sleep(0.02)

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())
        scan = [a for a in alerts if "port_scan" in a.event_type]
        self.assertGreater(len(scan), 0)

    def test_few_ports_no_alert(self):
        """Accessing a few ports should not trigger scan alert."""
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        for port in [80, 443, 8080]:  # just 3 ports
            eq.put(create_network_event("10.0.0.10", port))

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())
        scan = [a for a in alerts if "port_scan" in a.event_type]
        self.assertEqual(len(scan), 0)


class TestMultiSourceCorrelation(unittest.TestCase):
    """Test multi-source correlation rules."""

    def test_login_after_scan_critical(self):
        """Port scan + login should produce Critical alert."""
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        ip = "10.0.0.42"

        # Port scan events (network source)
        for port in range(config.FAST_SCAN_THRESHOLD + 2):
            eq.put(create_network_event(ip, port + 5000, is_malicious=True))
            time.sleep(0.02)

        time.sleep(0.5)

        # Login success (host source)
        eq.put(create_login_event(ip, "admin", True, True))

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())

        critical = [a for a in alerts if a.severity == config.SEVERITY_CRITICAL]
        self.assertGreater(len(critical), 0,
                           f"Expected Critical, got: {[(a.event_type, a.severity) for a in alerts]}")

    def test_suspicious_process_after_login(self):
        """Login + suspicious process should trigger alert."""
        eq = Queue()
        aq = Queue()
        engine = CorrelationEngine(eq, aq)
        engine.start()

        ip = "10.0.0.50"

        # Login success
        eq.put(create_login_event(ip, "hacker", True, True))
        time.sleep(0.2)

        # Suspicious process
        eq.put(create_process_event(ip, "hacker", "reverse_shell", True))

        time.sleep(2)
        engine.stop()

        alerts = []
        while not aq.empty():
            alerts.append(aq.get())

        proc_alerts = [a for a in alerts if a.event_type == "suspicious_process_after_login"]
        self.assertGreater(len(proc_alerts), 0)


if __name__ == "__main__":
    unittest.main()
