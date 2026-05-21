"""
main.py — Entry point for the Multi-Source Intrusion Detection System.

Supports two modes:
  1. Interactive: Starts the IDS and waits for user commands.
  2. Experiment: Runs all experiments automatically (delegates to run_experiments.py).

Usage:
  python main.py                 # Interactive mode
  python main.py --experiments   # Run all experiments
  python main.py --attack NAME   # Run a specific attack scenario
"""

import sys
import time
import threading
import logging
import argparse
from queue import Queue

import config
from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from attack_simulator import AttackSimulator

# ─── Logging Setup ────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("IDS.Main")


def setup_ids():
    """Create and wire all IDS components."""
    event_queue = Queue()
    alert_queue = Queue()

    net_enabled = threading.Event()
    net_enabled.set()
    host_enabled = threading.Event()
    host_enabled.set()

    network_sensor = NetworkSensor(event_queue, net_enabled)
    host_sensor = HostSensor(event_queue, host_enabled)
    correlation_engine = CorrelationEngine(event_queue, alert_queue)
    alert_manager = AlertManager(alert_queue)

    return {
        "event_queue": event_queue,
        "alert_queue": alert_queue,
        "network_sensor": network_sensor,
        "host_sensor": host_sensor,
        "correlation_engine": correlation_engine,
        "alert_manager": alert_manager,
    }


def start_ids(components: dict):
    """Start all IDS components."""
    components["alert_manager"].start()
    components["correlation_engine"].start()
    components["host_sensor"].start()
    # Network sensor with real sockets is optional
    # components["network_sensor"].start()
    logger.info("IDS system fully started.")


def stop_ids(components: dict):
    """Stop all IDS components."""
    components["network_sensor"].stop()
    components["host_sensor"].stop()
    components["correlation_engine"].stop()
    components["alert_manager"].stop()
    time.sleep(1)
    logger.info("IDS system stopped.")


def interactive_mode(components: dict):
    """Interactive CLI mode for manual testing."""
    simulator = AttackSimulator(
        network_sensor=components["network_sensor"],
        host_sensor=components["host_sensor"],
    )

    print("\n" + "=" * 60)
    print("  Multi-Source Intrusion Detection System")
    print("  Interactive Mode")
    print("=" * 60)
    print("\nAvailable commands:")
    print("  benign          - Generate benign traffic (10s)")
    print("  brute-force     - Launch brute-force login attack")
    print("  port-scan       - Launch fast port scan")
    print("  slow-scan       - Launch slow port scan")
    print("  noise           - Launch noise injection attack")
    print("  replay          - Launch replay attack")
    print("  sensor-fail     - Simulate sensor failure")
    print("  multi-step      - Launch multi-step attack")
    print("  alerts          - Show all alerts")
    print("  summary         - Show alert summary")
    print("  clear           - Clear alerts")
    print("  quit            - Exit")
    print()

    while True:
        try:
            cmd = input("IDS> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "benign":
            threading.Thread(
                target=simulator.generate_benign_traffic,
                args=(10.0, 3.0), daemon=True
            ).start()
        elif cmd == "brute-force":
            threading.Thread(
                target=simulator.attack_brute_force_login, daemon=True
            ).start()
        elif cmd == "port-scan":
            threading.Thread(
                target=simulator.attack_port_scan, daemon=True
            ).start()
        elif cmd == "slow-scan":
            threading.Thread(
                target=lambda: simulator.attack_port_scan(
                    scan_type="slow", num_ports=20, delay=2.0
                ),
                daemon=True,
            ).start()
        elif cmd == "noise":
            threading.Thread(
                target=simulator.attack_noise_injection, daemon=True
            ).start()
        elif cmd == "replay":
            threading.Thread(
                target=simulator.attack_replay, daemon=True
            ).start()
        elif cmd == "sensor-fail":
            threading.Thread(
                target=simulator.attack_sensor_failure, daemon=True
            ).start()
        elif cmd == "multi-step":
            threading.Thread(
                target=simulator.attack_multi_step, daemon=True
            ).start()
        elif cmd == "alerts":
            alerts = components["alert_manager"].get_alerts()
            if not alerts:
                print("  No alerts generated yet.")
            for a in alerts:
                print(f"  [{a.severity.upper()}] {a.alert_type}: {a.description}")
        elif cmd == "summary":
            summary = components["alert_manager"].get_alerts_summary()
            print(f"  Alert summary: {summary}")
            print(f"  Total: {components['alert_manager'].get_alert_count()}")
        elif cmd == "clear":
            components["alert_manager"].clear_alerts()
            print("  Alerts cleared.")
        elif cmd in ("quit", "exit", "q"):
            break
        elif cmd == "":
            continue
        else:
            print(f"  Unknown command: {cmd}")


def main():
    parser = argparse.ArgumentParser(description="Multi-Source IDS")
    parser.add_argument(
        "--experiments", action="store_true",
        help="Run all experiments automatically"
    )
    parser.add_argument(
        "--attack", type=str, default=None,
        help="Run a specific attack scenario"
    )
    args = parser.parse_args()

    if args.experiments:
        # Delegate to experiment runner
        from run_experiments import main as run_all
        run_all()
        return

    # Setup and start IDS
    components = setup_ids()
    start_ids(components)

    try:
        if args.attack:
            # Run specific attack
            simulator = AttackSimulator(
                network_sensor=components["network_sensor"],
                host_sensor=components["host_sensor"],
            )
            attacks = {
                "brute-force": simulator.attack_brute_force_login,
                "port-scan": simulator.attack_port_scan,
                "noise": simulator.attack_noise_injection,
                "replay": simulator.attack_replay,
                "sensor-fail": simulator.attack_sensor_failure,
                "multi-step": simulator.attack_multi_step,
            }
            attack_fn = attacks.get(args.attack)
            if attack_fn:
                logger.info(f"Running attack: {args.attack}")
                simulator.generate_benign_traffic(duration=5.0)
                attack_fn()
                time.sleep(config.EXPERIMENT_SETTLE_TIME)
                print(f"\nAlerts: {components['alert_manager'].get_alert_count()}")
                print(f"Summary: {components['alert_manager'].get_alerts_summary()}")
            else:
                print(f"Unknown attack: {args.attack}. Options: {list(attacks.keys())}")
        else:
            interactive_mode(components)
    finally:
        stop_ids(components)


if __name__ == "__main__":
    main()
