"""
test_event_schema.py — Tests for the unified event schema.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from event_schema import Event, create_network_event, create_login_event, create_process_event


class TestEventCreation(unittest.TestCase):
    """Test basic event creation and validation."""

    def test_create_valid_event(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type=config.EVENT_CONNECTION,
            severity=config.SEVERITY_INFO,
            src_ip="192.168.1.10",
            dst_port=80,
        )
        self.assertTrue(event.validate())
        self.assertEqual(event.source, config.SOURCE_NETWORK)
        self.assertEqual(event.dst_port, 80)
        self.assertIsNotNone(event.event_id)
        self.assertIsNotNone(event.timestamp)

    def test_invalid_source(self):
        event = Event(
            source="invalid_source",
            event_type=config.EVENT_CONNECTION,
        )
        with self.assertRaises(ValueError):
            event.validate()

    def test_invalid_event_type(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type="invalid_type",
        )
        with self.assertRaises(ValueError):
            event.validate()

    def test_invalid_severity(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type=config.EVENT_CONNECTION,
            severity="ultra_critical",
        )
        with self.assertRaises(ValueError):
            event.validate()


class TestEventSerialization(unittest.TestCase):
    """Test JSON serialization and deserialization."""

    def test_round_trip(self):
        original = Event(
            source=config.SOURCE_HOST,
            event_type=config.EVENT_LOGIN_ATTEMPT,
            severity=config.SEVERITY_LOW,
            src_ip="10.0.0.1",
            username="admin",
            status="failure",
            tags=["brute_force"],
        )
        data = original.to_dict()
        restored = Event.from_dict(data)

        self.assertEqual(restored.source, original.source)
        self.assertEqual(restored.event_type, original.event_type)
        self.assertEqual(restored.severity, original.severity)
        self.assertEqual(restored.src_ip, original.src_ip)
        self.assertEqual(restored.username, original.username)
        self.assertEqual(restored.status, original.status)
        self.assertEqual(restored.tags, original.tags)

    def test_to_dict_structure(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type=config.EVENT_CONNECTION,
            src_ip="1.2.3.4",
            dst_port=443,
        )
        d = event.to_dict()
        self.assertIn("event_id", d)
        self.assertIn("timestamp", d)
        self.assertIn("source", d)
        self.assertIn("event_type", d)
        self.assertIn("severity", d)
        self.assertIn("details", d)
        self.assertIn("tags", d)
        self.assertEqual(d["details"]["src_ip"], "1.2.3.4")
        self.assertEqual(d["details"]["dst_port"], 443)


class TestEventFactories(unittest.TestCase):
    """Test factory functions."""

    def test_create_network_event(self):
        event = create_network_event(
            src_ip="10.0.0.5",
            dst_port=8080,
            packet_count=5,
        )
        self.assertEqual(event.source, config.SOURCE_NETWORK)
        self.assertEqual(event.event_type, config.EVENT_CONNECTION)
        self.assertEqual(event.dst_port, 8080)
        self.assertEqual(event.packet_count, 5)
        self.assertTrue(event.validate())

    def test_create_login_event_failure(self):
        event = create_login_event(
            src_ip="10.0.0.1",
            username="admin",
            success=False,
        )
        self.assertEqual(event.source, config.SOURCE_HOST)
        self.assertEqual(event.event_type, config.EVENT_LOGIN_ATTEMPT)
        self.assertEqual(event.status, "failure")
        self.assertEqual(event.severity, config.SEVERITY_LOW)

    def test_create_login_event_success(self):
        event = create_login_event(
            src_ip="10.0.0.1",
            username="admin",
            success=True,
        )
        self.assertEqual(event.event_type, config.EVENT_LOGIN_SUCCESS)
        self.assertEqual(event.status, "success")
        self.assertEqual(event.severity, config.SEVERITY_INFO)

    def test_create_suspicious_process(self):
        event = create_process_event(
            src_ip="10.0.0.1",
            username="admin",
            process_name="netcat",
        )
        self.assertEqual(event.event_type, config.EVENT_PROCESS_EXEC)
        self.assertEqual(event.severity, config.SEVERITY_MEDIUM)
        self.assertIn("suspicious_process", event.tags)

    def test_create_normal_process(self):
        event = create_process_event(
            src_ip="10.0.0.1",
            username="user",
            process_name="vim",
        )
        self.assertEqual(event.severity, config.SEVERITY_INFO)
        self.assertNotIn("suspicious_process", event.tags)

    def test_malicious_flag(self):
        event = create_network_event(
            src_ip="10.0.0.1",
            dst_port=80,
            is_malicious=True,
        )
        self.assertTrue(event.is_malicious)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases in event handling."""

    def test_empty_tags_default(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type=config.EVENT_CONNECTION,
        )
        self.assertEqual(event.tags, [])

    def test_empty_ip(self):
        event = Event(
            source=config.SOURCE_NETWORK,
            event_type=config.EVENT_CONNECTION,
            src_ip="",
        )
        self.assertTrue(event.validate())

    def test_from_dict_with_missing_details(self):
        data = {
            "source": config.SOURCE_NETWORK,
            "event_type": config.EVENT_CONNECTION,
        }
        event = Event.from_dict(data)
        self.assertEqual(event.src_ip, "")
        self.assertEqual(event.dst_port, 0)

    def test_from_dict_preserves_epoch(self):
        data = {
            "source": config.SOURCE_NETWORK,
            "event_type": config.EVENT_CONNECTION,
            "epoch": 1234567890.0,
        }
        event = Event.from_dict(data)
        self.assertEqual(event.epoch, 1234567890.0)


if __name__ == "__main__":
    unittest.main()
