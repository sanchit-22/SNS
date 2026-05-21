"""
host_sensor.py — Host Sensor module for the Multi-Source IDS.

Monitors synthetic host-level events: login attempts, process execution,
privilege escalation. Events are generated via the attack simulator or
injected directly for testing.
"""

import threading
import time
import json
import os
import logging
from queue import Queue
from typing import Optional

import config
from event_schema import Event, create_login_event, create_process_event

logger = logging.getLogger("IDS.HostSensor")


class HostSensor:
    """
    Host sensor that monitors synthetic host logs for security-relevant events.
    Watches a log file (host_events.log) for new entries and also accepts
    direct event injection.
    """

    def __init__(self, event_queue: Queue, enabled_flag: Optional[threading.Event] = None):
        """
        Args:
            event_queue: Thread-safe queue to push events to correlation engine.
            enabled_flag: If set (default), sensor is active. Clear to disable.
        """
        self.event_queue = event_queue
        self.enabled = enabled_flag or threading.Event()
        self.enabled.set()
        self._stop_event = threading.Event()
        self._thread = None
        self._log_file = config.HOST_LOG_FILE

    def start(self):
        """Start the host sensor — monitors the log file."""
        logger.info("Host Sensor starting...")

        # Create log file if it doesn't exist
        if not os.path.exists(self._log_file):
            with open(self._log_file, "w") as f:
                pass

        self._thread = threading.Thread(target=self._monitor_log, daemon=True)
        self._thread.start()
        logger.info(f"Host Sensor monitoring: {self._log_file}")

    def stop(self):
        """Stop the host sensor gracefully."""
        logger.info("Host Sensor stopping...")
        self._stop_event.set()

    def disable(self):
        """Simulate sensor failure."""
        logger.warning("Host Sensor DISABLED (sensor failure simulation)")
        self.enabled.clear()

    def enable(self):
        """Re-enable the sensor."""
        logger.info("Host Sensor re-enabled")
        self.enabled.set()

    def _monitor_log(self):
        """Tail-follow the host log file for new entries."""
        # Move to end of file
        with open(self._log_file, "r") as f:
            f.seek(0, 2)  # seek to end
            while not self._stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                if not self.enabled.is_set():
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    event = Event.from_dict(data)
                    event.validate()
                    self.event_queue.put(event)
                    logger.debug(f"Host event: {event}")
                except (json.JSONDecodeError, ValueError, KeyError) as e:
                    logger.warning(f"Malformed host log entry: {e}")

    def inject_event(self, event: Event):
        """
        Directly inject a host event into the queue (used by attack simulator).
        Also writes to the log file for audit trail.
        """
        if not self.enabled.is_set():
            logger.debug("Host sensor disabled, dropping injected event")
            return

        try:
            event.validate()
            self.event_queue.put(event)

            # Also append to log file
            with open(self._log_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")

            logger.debug(f"Injected host event: {event}")
        except ValueError as e:
            logger.error(f"Invalid injected host event: {e}")

    def write_log_entry(self, event: Event):
        """Write a raw event to the log file (for file-based monitoring)."""
        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except IOError as e:
            logger.error(f"Failed to write host log: {e}")
