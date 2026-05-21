"""
metrics.py — Metrics computation for the Multi-Source IDS.

Computes Precision, Recall, F1-score, False Positive/Negative rates,
alert generation latency, and CPU/memory usage.
"""

import time
import os
import logging
from typing import List, Tuple, Dict, Optional

import config
from event_schema import Event
from alert_manager import Alert

logger = logging.getLogger("IDS.Metrics")

# Try importing psutil for resource monitoring (optional dependency)
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed — CPU/memory metrics will be unavailable")


class MetricsCollector:
    """
    Collects and computes evaluation metrics for IDS experiments.
    """

    def __init__(self):
        self.experiment_start_time = 0
        self.experiment_end_time = 0
        self._event_injection_times: Dict[str, float] = {}  # event_id -> inject time
        self._alert_generation_times: Dict[str, float] = {}  # alert_id -> alert time

    def start_experiment(self):
        """Mark the start of an experiment."""
        self.experiment_start_time = time.time()
        self._event_injection_times.clear()
        self._alert_generation_times.clear()

    def end_experiment(self):
        """Mark the end of an experiment."""
        self.experiment_end_time = time.time()

    def record_event_injection(self, event_id: str):
        """Record when an event was injected (for latency)."""
        self._event_injection_times[event_id] = time.time()

    def record_alert_generation(self, alert_id: str):
        """Record when an alert was generated (for latency)."""
        self._alert_generation_times[alert_id] = time.time()

    def compute_metrics(
        self,
        alerts: List[Alert],
        ground_truth: List[Tuple[Event, bool]],
    ) -> dict:
        """
        Compute all evaluation metrics.

        Args:
            alerts: List of generated alerts.
            ground_truth: List of (event, is_malicious) tuples.

        Returns:
            Dictionary with all metrics.
        """
        # Separate malicious and benign ground truth
        malicious_ips = set()
        benign_ips = set()
        total_malicious = 0
        total_benign = 0

        for event, is_mal in ground_truth:
            if is_mal:
                malicious_ips.add(event.src_ip)
                total_malicious += 1
            else:
                benign_ips.add(event.src_ip)
                total_benign += 1

        # Only IPs that are exclusively benign (never malicious)
        pure_benign_ips = benign_ips - malicious_ips

        # Classify alerts
        alerted_ips = {a.src_ip for a in alerts}

        # True Positives: malicious IPs that generated alerts
        tp = len(malicious_ips & alerted_ips)
        # False Positives: purely benign IPs that generated alerts
        fp = len(pure_benign_ips & alerted_ips)
        # False Negatives: malicious IPs that did NOT generate alerts
        fn = len(malicious_ips - alerted_ips)
        # True Negatives: purely benign IPs that did NOT generate alerts
        tn = len(pure_benign_ips - alerted_ips)

        # Precision, Recall, F1
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # FP/FN rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Alert latency (average time from experiment start to alert)
        latencies = []
        for alert in alerts:
            latency = alert.timestamp - self.experiment_start_time
            if latency >= 0:
                latencies.append(latency)
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        # Resource usage
        cpu_percent = 0.0
        memory_mb = 0.0
        if HAS_PSUTIL:
            process = psutil.Process(os.getpid())
            cpu_percent = process.cpu_percent(interval=0.5)
            memory_mb = process.memory_info().rss / (1024 * 1024)

        # Experiment duration
        duration = self.experiment_end_time - self.experiment_start_time

        metrics = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "total_alerts": len(alerts),
            "total_malicious_events": total_malicious,
            "total_benign_events": total_benign,
            "avg_alert_latency_seconds": round(avg_latency, 4),
            "experiment_duration_seconds": round(duration, 4),
            "cpu_percent": round(cpu_percent, 2),
            "memory_mb": round(memory_mb, 2),
            "alerts_by_severity": {},
        }

        # Alerts by severity
        for sev in config.SEVERITY_ORDER:
            sev_alerts = [a for a in alerts if a.severity == sev]
            metrics["alerts_by_severity"][sev] = len(sev_alerts)

        return metrics

    def format_metrics(self, metrics: dict) -> str:
        """Format metrics as a human-readable table."""
        c = config.Colors
        lines = [
            "\n" + c.HEADER + "=" * 60,
            "  EXPERIMENT METRICS",
            "=" * 60 + c.ENDC,
            f"  Duration:           {metrics['experiment_duration_seconds']:.2f}s",
            "",
            c.OKBLUE + "  ── Detection Performance ──" + c.ENDC,
            f"  True Positives:     {c.OKGREEN}{metrics['true_positives']}{c.ENDC}",
            f"  False Positives:    {c.FAIL if metrics['false_positives'] > 0 else c.OKGREEN}{metrics['false_positives']}{c.ENDC}",
            f"  False Negatives:    {c.FAIL if metrics['false_negatives'] > 0 else c.OKGREEN}{metrics['false_negatives']}{c.ENDC}",
            f"  True Negatives:     {metrics['true_negatives']}",
            f"  Precision:          {c.OKGREEN if metrics['precision'] >= 0.8 else c.WARNING}{metrics['precision']:.4f}{c.ENDC}",
            f"  Recall:             {c.OKGREEN if metrics['recall'] >= 0.8 else c.WARNING}{metrics['recall']:.4f}{c.ENDC}",
            f"  F1-Score:           {c.OKGREEN if metrics['f1_score'] >= 0.8 else c.WARNING}{metrics['f1_score']:.4f}{c.ENDC}",
            f"  FP Rate:            {c.FAIL if metrics['false_positive_rate'] > 0 else c.OKGREEN}{metrics['false_positive_rate']:.4f}{c.ENDC}",
            f"  FN Rate:            {c.FAIL if metrics['false_negative_rate'] > 0 else c.OKGREEN}{metrics['false_negative_rate']:.4f}{c.ENDC}",
            "",
            c.OKBLUE + "  ── Alert Summary ──" + c.ENDC,
            f"  Total Alerts:       {c.BOLD}{metrics['total_alerts']}{c.ENDC}",
            f"  Malicious Events:   {metrics['total_malicious_events']}",
            f"  Benign Events:      {metrics['total_benign_events']}",
            f"  Avg Latency:        {metrics['avg_alert_latency_seconds']:.4f}s",
            "",
            c.OKBLUE + "  ── Alerts by Severity ──" + c.ENDC,
        ]
        for sev, count in metrics.get("alerts_by_severity", {}).items():
            color = config.SEVERITY_COLORS.get(sev, c.ENDC)
            lines.append(f"  {color}{sev:>12}{c.ENDC}: {count}")

        if metrics.get("cpu_percent") or metrics.get("memory_mb"):
            lines.extend([
                "",
                c.OKBLUE + "  ── Resource Usage ──" + c.ENDC,
                f"  CPU:                {metrics['cpu_percent']}%",
                f"  Memory:             {metrics['memory_mb']:.2f} MB",
            ])

        lines.append(c.HEADER + "=" * 60 + c.ENDC)
        return "\n".join(lines)
