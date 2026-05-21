"""
network_sensor.py — Network Sensor module for the Multi-Source IDS.

Captures network-level activity on localhost using socket-based monitoring.
Emits normalized JSON events to the correlation engine via a shared queue.
"""

import socket
import threading
import time
import logging
from queue import Queue
from typing import Optional

import config
from event_schema import Event, create_network_event

logger = logging.getLogger("IDS.NetworkSensor")


class NetworkSensor:
    """
    Network sensor that monitors connections on localhost ports.
    Uses a simple TCP server per monitored port to detect incoming connections.
    Can be disabled (for sensor-failure simulation) via an event flag.
    """

    def __init__(self, event_queue: Queue, enabled_flag: Optional[threading.Event] = None):
        """
        Args:
            event_queue: Thread-safe queue to push events to the correlation engine.
            enabled_flag: If set (default), sensor is active. Clear to disable.
        """
        self.event_queue = event_queue
        self.enabled = enabled_flag or threading.Event()
        self.enabled.set()  # enabled by default
        self._stop_event = threading.Event()
        self._threads = []
        self._server_sockets = []

        # Connection tracking for flow aggregation
        self._flows = {}  # (src_ip, dst_port) -> {count, bytes, first_seen, last_seen}
        self._flow_lock = threading.Lock()

    def start(self):
        """Start the network sensor — listens on configured ports."""
        logger.info("Network Sensor starting...")

        # Start flow aggregation thread
        flow_thread = threading.Thread(target=self._flow_aggregator, daemon=True)
        flow_thread.start()
        self._threads.append(flow_thread)

        # Start listener threads for a range of ports
        for port in range(config.NETWORK_LISTEN_PORT_START, config.NETWORK_LISTEN_PORT_END + 1):
            t = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            t.start()
            self._threads.append(t)

        logger.info(
            f"Network Sensor listening on ports "
            f"{config.NETWORK_LISTEN_PORT_START}-{config.NETWORK_LISTEN_PORT_END}"
        )

    def stop(self):
        """Stop the network sensor gracefully."""
        logger.info("Network Sensor stopping...")
        self._stop_event.set()
        # Close all server sockets to unblock accept()
        for sock in self._server_sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._server_sockets.clear()

    def disable(self):
        """Simulate sensor failure — stop processing events."""
        logger.warning("Network Sensor DISABLED (sensor failure simulation)")
        self.enabled.clear()

    def enable(self):
        """Re-enable the sensor after simulated failure."""
        logger.info("Network Sensor re-enabled")
        self.enabled.set()

    def _listen_on_port(self, port: int):
        """Listen on a single port for incoming connections."""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(1.0)  # so we can check _stop_event periodically
            server_sock.bind((config.NETWORK_LISTEN_HOST, port))
            server_sock.listen(5)
            self._server_sockets.append(server_sock)
        except OSError as e:
            # Port might already be in use — skip silently
            logger.debug(f"Cannot bind port {port}: {e}")
            return

        while not self._stop_event.is_set():
            try:
                client_sock, addr = server_sock.accept()
                client_sock.close()

                if not self.enabled.is_set():
                    continue  # sensor disabled, drop the event

                src_ip = addr[0]
                self._record_connection(src_ip, port)

            except socket.timeout:
                continue
            except OSError:
                break

        try:
            server_sock.close()
        except Exception:
            pass

    def _record_connection(self, src_ip: str, dst_port: int):
        """Record a connection for flow aggregation."""
        now = time.time()
        key = (src_ip, dst_port)

        with self._flow_lock:
            if key in self._flows:
                self._flows[key]["count"] += 1
                self._flows[key]["last_seen"] = now
            else:
                self._flows[key] = {
                    "count": 1,
                    "first_seen": now,
                    "last_seen": now,
                }

    def _flow_aggregator(self):
        """Periodically flush aggregated flows as events."""
        while not self._stop_event.is_set():
            time.sleep(config.FLOW_BUCKET_SECONDS)

            if not self.enabled.is_set():
                continue

            with self._flow_lock:
                flows_to_emit = dict(self._flows)
                self._flows.clear()

            for (src_ip, dst_port), flow_data in flows_to_emit.items():
                event = create_network_event(
                    src_ip=src_ip,
                    dst_port=dst_port,
                    packet_count=flow_data["count"],
                    byte_count=flow_data["count"] * 64,  # estimated
                )
                try:
                    event.validate()
                    self.event_queue.put(event)
                    logger.debug(f"Network event: {src_ip} -> port {dst_port} (x{flow_data['count']})")
                except ValueError as e:
                    logger.error(f"Invalid network event: {e}")

    def inject_event(self, event: Event):
        """
        Directly inject a synthetic network event (used by attack simulator).
        Bypasses the socket listener — used for testing.
        """
        if not self.enabled.is_set():
            logger.debug("Network sensor disabled, dropping injected event")
            return

        try:
            event.validate()
            self.event_queue.put(event)
            logger.debug(f"Injected network event: {event}")
        except ValueError as e:
            logger.error(f"Invalid injected event: {e}")
