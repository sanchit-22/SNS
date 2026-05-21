"""
run_experiments.py — Automated Experiment Runner for the Multi-Source IDS.

Runs all attack scenarios sequentially, collects alerts and metrics,
and saves results to the results/ directory.
"""

import os
import sys
import json
import time
import threading
import logging
from queue import Queue

import config
from event_schema import Event
from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from attack_simulator import AttackSimulator
from metrics import MetricsCollector

# ─── Logging Setup ────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("IDS.Experiments")


class IDSSystem:
    """Manages all IDS components as a cohesive system."""

    def __init__(self):
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

    def start(self):
        """Start all IDS components."""
        logger.info("Starting IDS system...")
        self.alert_manager.start()
        self.correlation_engine.start()
        self.host_sensor.start()
        # Note: Network sensor with real sockets is optional
        # self.network_sensor.start()
        logger.info("IDS system started (injection mode).")

    def stop(self):
        """Stop all IDS components."""
        logger.info("Stopping IDS system...")
        self.network_sensor.stop()
        self.host_sensor.stop()
        self.correlation_engine.stop()
        self.alert_manager.stop()
        time.sleep(1)  # Let threads wind down
        logger.info("IDS system stopped.")

    def reset(self):
        """Reset state between experiments."""
        self.alert_manager.clear_alerts()
        self.net_enabled.set()
        self.host_enabled.set()
        # Clear host log file
        with open(config.HOST_LOG_FILE, "w") as f:
            pass


def run_single_experiment(
    ids: IDSSystem,
    experiment_name: str,
    attack_fn,
    metrics_collector: MetricsCollector,
    simulator: AttackSimulator,
) -> dict:
    """
    Run a single experiment following the structured workflow:
    1. Reset state
    2. Generate benign baseline
    3. Execute attack
    4. Wait for detection
    5. Collect metrics
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"  EXPERIMENT: {experiment_name}")
    logger.info(f"{'='*60}")

    # Reset
    ids.reset()
    simulator.clear_ground_truth()
    metrics_collector.start_experiment()

    # Step 1: Generate benign baseline
    logger.info("Phase 1: Generating benign baseline...")
    simulator.generate_benign_traffic(
        duration=config.BENIGN_BASELINE_DURATION,
        rate=3.0,
    )

    # Step 2: Execute attack
    logger.info(f"Phase 2: Executing attack — {experiment_name}")
    attack_fn()

    # Step 3: Wait for correlation and alert processing
    logger.info("Phase 3: Waiting for detection pipeline to settle...")
    time.sleep(config.EXPERIMENT_SETTLE_TIME)

    # Step 4: Collect results
    metrics_collector.end_experiment()
    alerts = ids.alert_manager.get_alerts()
    ground_truth = simulator.ground_truth

    metrics = metrics_collector.compute_metrics(alerts, ground_truth)
    metrics["experiment_name"] = experiment_name

    # Print metrics
    print(metrics_collector.format_metrics(metrics))

    return metrics


def main():
    """Run all experiments."""
    # Create results directory
    os.makedirs(config.RESULTS_DIR, exist_ok=True)

    # Initialize IDS
    ids = IDSSystem()
    ids.start()

    # Initialize simulator (injection mode — no real sockets)
    simulator = AttackSimulator(
        network_sensor=ids.network_sensor,
        host_sensor=ids.host_sensor,
        use_real_sockets=False,
    )

    metrics_collector = MetricsCollector()
    all_results = []

    # ─── Define experiments ───────────────────────────────────────────

    experiments = [
        (
            "Brute-Force Login",
            lambda: simulator.attack_brute_force_login(
                attacker_ip="10.0.0.99",
                target_user="admin",
                num_attempts=20,
                succeed_at_end=True,
            ),
        ),
        (
            "Fast Port Scan",
            lambda: simulator.attack_port_scan(
                attacker_ip="10.0.0.88",
                num_ports=50,
                scan_type="fast",
            ),
        ),
        (
            "Slow Port Scan",
            lambda: simulator.attack_port_scan(
                attacker_ip="10.0.0.87",
                num_ports=20,
                delay=2.0,
                scan_type="slow",
            ),
        ),
        (
            "Noise Injection",
            lambda: simulator.attack_noise_injection(
                num_noise_events=100,
                num_hidden_malicious=5,
            ),
        ),
        (
            "Replay Attack",
            lambda: simulator.attack_replay(
                attacker_ip="10.0.0.66",
                num_replays=20,
            ),
        ),
        (
            "Sensor Failure",
            lambda: simulator.attack_sensor_failure(
                disable_network=True,
                failure_duration=5.0,
                attack_during_failure=True,
            ),
        ),
        (
            "Multi-Step Attack",
            lambda: simulator.attack_multi_step(
                attacker_ip="10.0.0.42",
            ),
        ),
    ]

    # ─── Run experiments ──────────────────────────────────────────────

    for exp_name, attack_fn in experiments:
        try:
            result = run_single_experiment(
                ids, exp_name, attack_fn, metrics_collector, simulator
            )
            all_results.append(result)

            # Save individual result
            result_file = os.path.join(
                config.RESULTS_DIR,
                f"experiment_{exp_name.lower().replace(' ', '_')}.json",
            )
            with open(result_file, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Results saved to {result_file}")

        except Exception as e:
            logger.error(f"Experiment '{exp_name}' failed: {e}", exc_info=True)
            all_results.append({"experiment_name": exp_name, "error": str(e)})

    # ─── Save aggregate results ───────────────────────────────────────
    aggregate_file = os.path.join(config.RESULTS_DIR, "all_experiments.json")
    with open(aggregate_file, "w") as f:
        json.dump(all_results, f, indent=2)

    # ─── Print summary ────────────────────────────────────────────────
    print("\n" + config.Colors.HEADER + "=" * 60)
    print("  AGGREGATE RESULTS SUMMARY")
    print("=" * 60 + config.Colors.ENDC)
    for result in all_results:
        name = result.get("experiment_name", "Unknown")
        if "error" in result:
            print(f"  ❌ {config.Colors.FAIL}{name}: ERROR — {result['error']}{config.Colors.ENDC}")
        else:
            passing = result['precision'] > 0.5
            color = config.Colors.OKGREEN if passing else config.Colors.WARNING
            msg = (f"P={result['precision']:.3f} R={result['recall']:.3f} "
                   f"F1={result['f1_score']:.3f} Alerts={result['total_alerts']}")
            print(f"  {'✅' if passing else '⚠️'} {config.Colors.BOLD}{name}{config.Colors.ENDC}: {color}{msg}{config.Colors.ENDC}")
    print(config.Colors.HEADER + "=" * 60 + config.Colors.ENDC)
    print(f"\nAll results saved to {config.Colors.OKCYAN}{config.RESULTS_DIR}/{config.Colors.ENDC}")

    # Stop IDS
    ids.stop()


if __name__ == "__main__":
    main()
