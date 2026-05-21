"""
attack_simulator.py — Attack Simulator for the Multi-Source IDS.

Generates both benign and malicious activity for testing.
Implements 5 attack scenarios:
  1. Brute-force login
  2. Port scanning (fast + slow)
  3. Noise injection
  4. Replay attack
  5. Sensor failure simulation
"""

import time
import random
import socket
import threading
import logging
from typing import Optional

import config
from event_schema import (
    Event, create_network_event, create_login_event, create_process_event,
)

logger = logging.getLogger("IDS.AttackSimulator")


class AttackSimulator:
    """
    Generates traffic/events for testing the IDS.
    Works by injecting events directly into sensors (for speed and reliability)
    and optionally making real socket connections.
    """

    def __init__(
        self,
        network_sensor=None,
        host_sensor=None,
        use_real_sockets: bool = False,
    ):
        self.network_sensor = network_sensor
        self.host_sensor = host_sensor
        self.use_real_sockets = use_real_sockets
        self._ground_truth = []  # list of (event, is_malicious) for metrics

    @property
    def ground_truth(self):
        return list(self._ground_truth)

    def clear_ground_truth(self):
        self._ground_truth.clear()

    # ─── Benign Traffic ────────────────────────────────────────────────

    def generate_benign_traffic(self, duration: float = 10.0, rate: float = 2.0):
        """
        Generate normal, benign traffic to establish baseline.

        Args:
            duration: How long to generate traffic (seconds).
            rate: Events per second.
        """
        logger.info(f"Generating benign traffic for {duration}s at {rate} events/s...")
        end_time = time.time() + duration
        benign_users = ["alice", "bob", "charlie", "diana"]
        benign_ports = [80, 443, 8080, 22, 3306]

        while time.time() < end_time:
            # Random benign network connection
            if self.network_sensor and random.random() < 0.6:
                port = random.choice(benign_ports)
                event = create_network_event(
                    src_ip="192.168.1." + str(random.randint(10, 50)),
                    dst_port=port,
                    packet_count=random.randint(1, 10),
                    byte_count=random.randint(64, 1500),
                    is_malicious=False,
                )
                self.network_sensor.inject_event(event)
                self._ground_truth.append((event, False))

            # Random benign login (mostly successful)
            if self.host_sensor and random.random() < 0.4:
                user = random.choice(benign_users)
                success = random.random() < 0.9  # 90% success rate
                event = create_login_event(
                    src_ip="192.168.1." + str(random.randint(10, 50)),
                    username=user,
                    success=success,
                    is_malicious=False,
                )
                self.host_sensor.inject_event(event)
                self._ground_truth.append((event, False))

            # Random benign process
            if self.host_sensor and random.random() < 0.2:
                event = create_process_event(
                    src_ip="192.168.1." + str(random.randint(10, 50)),
                    username=random.choice(benign_users),
                    process_name=random.choice(["vim", "ls", "cat", "grep", "firefox"]),
                    is_malicious=False,
                )
                self.host_sensor.inject_event(event)
                self._ground_truth.append((event, False))

            time.sleep(1.0 / rate)

        logger.info("Benign traffic generation complete.")

    # ─── Attack Scenario 1: Brute-Force Login ──────────────────────────

    def attack_brute_force_login(
        self,
        attacker_ip: str = "10.0.0.99",
        target_user: str = "admin",
        num_attempts: int = 20,
        delay: float = 0.1,
        succeed_at_end: bool = True,
    ):
        """
        Simulate brute-force SSH login attempts.

        Args:
            attacker_ip: Source IP of the attacker.
            target_user: Username being targeted.
            num_attempts: Number of failed login attempts.
            delay: Time between attempts (seconds).
            succeed_at_end: If True, last attempt succeeds (credential compromise).
        """
        logger.info(
            f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} Brute-force login from {attacker_ip} targeting '{target_user}' "
            f"({num_attempts} attempts)"
        )

        for i in range(num_attempts):
            event = create_login_event(
                src_ip=attacker_ip,
                username=target_user,
                success=False,
                is_malicious=True,
                tags=["brute_force"],
            )
            if self.host_sensor:
                self.host_sensor.inject_event(event)
            self._ground_truth.append((event, True))
            time.sleep(delay)

        if succeed_at_end:
            # Successful login after brute-force
            time.sleep(0.5)
            event = create_login_event(
                src_ip=attacker_ip,
                username=target_user,
                success=True,
                is_malicious=True,
                tags=["brute_force", "credential_compromise"],
            )
            if self.host_sensor:
                self.host_sensor.inject_event(event)
            self._ground_truth.append((event, True))

            # Also generate a network event from the same IP (multi-source)
            if self.network_sensor:
                net_event = create_network_event(
                    src_ip=attacker_ip,
                    dst_port=22,
                    packet_count=num_attempts + 1,
                    is_malicious=True,
                    tags=["brute_force"],
                )
                self.network_sensor.inject_event(net_event)
                self._ground_truth.append((net_event, True))

        logger.info("Brute-force attack complete.")

    # ─── Attack Scenario 2: Port Scanning ──────────────────────────────

    def attack_port_scan(
        self,
        attacker_ip: str = "10.0.0.88",
        num_ports: int = 50,
        delay: float = 0.05,
        scan_type: str = "fast",
    ):
        """
        Simulate port scanning.

        Args:
            attacker_ip: Source IP.
            num_ports: Number of ports to scan.
            delay: Time between probes (fast=0.05, slow=2.0).
            scan_type: "fast" or "slow".
        """
        if scan_type == "slow":
            delay = max(delay, 1.0)  # ensure slow scan is actually slow

        logger.info(
            f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} {scan_type.capitalize()} port scan from {attacker_ip} "
            f"({num_ports} ports, delay={delay}s)"
        )

        ports = random.sample(range(1, 65535), min(num_ports, 65534))

        for port in ports:
            event = create_network_event(
                src_ip=attacker_ip,
                dst_port=port,
                packet_count=1,
                byte_count=40,
                is_malicious=True,
                tags=["port_scan", scan_type],
            )
            if self.network_sensor:
                self.network_sensor.inject_event(event)
            self._ground_truth.append((event, True))

            if self.use_real_sockets:
                self._try_connect(attacker_ip, port)

            time.sleep(delay)

        logger.info(f"{scan_type.capitalize()} port scan complete.")

    # ─── Attack Scenario 3: Noise Injection ────────────────────────────

    def attack_noise_injection(
        self,
        num_noise_events: int = 100,
        num_hidden_malicious: int = 5,
        delay: float = 0.05,
    ):
        """
        Generate heavy benign-looking traffic with subtle malicious signals hidden.

        Args:
            num_noise_events: Total noise events.
            num_hidden_malicious: Malicious events hidden in noise.
            delay: Time between events.
        """
        logger.info(
            f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} Noise injection ({num_noise_events} noise + "
            f"{num_hidden_malicious} hidden malicious)"
        )

        benign_ips = [f"192.168.1.{i}" for i in range(10, 60)]
        attacker_ip = "10.0.0.77"
        malicious_indices = set(
            random.sample(range(num_noise_events), min(num_hidden_malicious, num_noise_events))
        )

        for i in range(num_noise_events):
            if i in malicious_indices:
                # Hidden malicious event
                event = create_login_event(
                    src_ip=attacker_ip,
                    username="root",
                    success=False,
                    is_malicious=True,
                    tags=["noise_injection", "hidden"],
                )
                self._ground_truth.append((event, True))
            else:
                # Benign noise
                ip = random.choice(benign_ips)
                if random.random() < 0.5:
                    event = create_network_event(
                        src_ip=ip,
                        dst_port=random.choice([80, 443, 8080]),
                        is_malicious=False,
                    )
                else:
                    event = create_login_event(
                        src_ip=ip,
                        username=random.choice(["alice", "bob", "charlie"]),
                        success=True,
                        is_malicious=False,
                    )
                self._ground_truth.append((event, False))

            if event.source == config.SOURCE_HOST and self.host_sensor:
                self.host_sensor.inject_event(event)
            elif event.source == config.SOURCE_NETWORK and self.network_sensor:
                self.network_sensor.inject_event(event)

            time.sleep(delay)

        logger.info("Noise injection complete.")

    # ─── Attack Scenario 4: Replay Attack ──────────────────────────────

    def attack_replay(
        self,
        attacker_ip: str = "10.0.0.66",
        num_replays: int = 20,
        delay: float = 0.1,
    ):
        """
        Capture a benign traffic pattern and replay with slight modifications.

        Args:
            attacker_ip: IP to replay traffic from.
            num_replays: Number of replayed events.
            delay: Time between replayed events.
        """
        logger.info(f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} Replay attack from {attacker_ip} ({num_replays} replays)")

        # First, generate some benign "captured" traffic pattern
        captured_events = []
        benign_ports = [80, 443, 8080]
        for _ in range(5):
            evt = create_network_event(
                src_ip="192.168.1.20",
                dst_port=random.choice(benign_ports),
                packet_count=random.randint(1, 5),
            )
            captured_events.append(evt)

        # Replay captured traffic from attacker IP with slight timing changes
        for i in range(num_replays):
            template = random.choice(captured_events)
            replayed = create_network_event(
                src_ip=attacker_ip,
                dst_port=template.dst_port,
                packet_count=template.packet_count + random.randint(-1, 2),
                byte_count=template.byte_count + random.randint(-10, 10),
                is_malicious=True,
                tags=["replay"],
            )
            if self.network_sensor:
                self.network_sensor.inject_event(replayed)
            self._ground_truth.append((replayed, True))

            # Also inject matching login attempts (replay of auth)
            if random.random() < 0.3 and self.host_sensor:
                login_event = create_login_event(
                    src_ip=attacker_ip,
                    username="admin",
                    success=random.random() < 0.2,
                    is_malicious=True,
                    tags=["replay"],
                )
                self.host_sensor.inject_event(login_event)
                self._ground_truth.append((login_event, True))

            time.sleep(delay + random.uniform(-0.02, 0.05))

        logger.info("Replay attack complete.")

    # ─── Attack Scenario 5: Sensor Failure ─────────────────────────────

    def attack_sensor_failure(
        self,
        disable_network: bool = True,
        failure_duration: float = 15.0,
        attack_during_failure: bool = True,
    ):
        """
        Simulate a sensor being temporarily disabled.
        Tests if the IDS degrades gracefully.

        Args:
            disable_network: If True, disable network sensor. Else host sensor.
            failure_duration: How long the sensor is down.
            attack_during_failure: If True, launch attacks while sensor is down.
        """
        sensor_name = "Network" if disable_network else "Host"
        sensor = self.network_sensor if disable_network else self.host_sensor

        logger.info(
            f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} Sensor failure simulation — disabling {sensor_name} sensor "
            f"for {failure_duration}s"
        )

        if sensor:
            sensor.disable()

        if attack_during_failure:
            # Launch brute-force while network sensor is down
            # Only host sensor should detect this
            self.attack_brute_force_login(
                attacker_ip="10.0.0.55",
                target_user="root",
                num_attempts=10,
                delay=0.2,
                succeed_at_end=False,
            )

        # Wait then re-enable
        time.sleep(failure_duration)

        if sensor:
            sensor.enable()

        logger.info(f"{sensor_name} sensor re-enabled after failure simulation.")

    # ─── Multi-Step Attack (Combo) ─────────────────────────────────────

    def attack_multi_step(
        self,
        attacker_ip: str = "10.0.0.42",
    ):
        """
        Execute a multi-step attack: scan → brute-force → process exec.
        This should trigger Critical alerts via multi-source correlation.
        """
        logger.info(f"{config.Colors.FAIL}{config.Colors.BOLD}ATTACK:{config.Colors.ENDC} Multi-step attack from {attacker_ip}")

        # Step 1: Port scan (network sensor)
        self.attack_port_scan(
            attacker_ip=attacker_ip,
            num_ports=15,
            delay=0.05,
            scan_type="fast",
        )
        time.sleep(1)

        # Step 2: Brute-force login (host sensor + network sensor)
        self.attack_brute_force_login(
            attacker_ip=attacker_ip,
            target_user="admin",
            num_attempts=10,
            delay=0.1,
            succeed_at_end=True,
        )
        time.sleep(1)

        # Step 3: Suspicious process execution (host sensor)
        event = create_process_event(
            src_ip=attacker_ip,
            username="admin",
            process_name="reverse_shell",
            is_malicious=True,
            tags=["post_exploitation"],
        )
        if self.host_sensor:
            self.host_sensor.inject_event(event)
        self._ground_truth.append((event, True))

        logger.info("Multi-step attack complete.")

    # ─── Helper ────────────────────────────────────────────────────────

    def _try_connect(self, target_ip: str, port: int):
        """Attempt a real TCP connection (for real socket testing)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((config.NETWORK_LISTEN_HOST, port))
            sock.close()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
