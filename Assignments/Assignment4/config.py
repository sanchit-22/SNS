"""
config.py — Central configuration for the Multi-Source IDS.
All tuneable constants, thresholds, and window sizes live here.
"""

# ─── Severity Levels ──────────────────────────────────────────────────
SEVERITY_INFO = "info"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

# Scoring weights per severity
SEVERITY_WEIGHTS = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 3,
    SEVERITY_HIGH: 5,
    SEVERITY_CRITICAL: 10,
}

# ─── Event Sources ────────────────────────────────────────────────────
SOURCE_NETWORK = "network_sensor"
SOURCE_HOST = "host_sensor"
SOURCE_CORRELATION = "correlation_engine"

# ─── Event Types ──────────────────────────────────────────────────────
EVENT_CONNECTION = "connection"
EVENT_PORT_SCAN = "port_scan"
EVENT_LOGIN_ATTEMPT = "login_attempt"
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_PROCESS_EXEC = "process_exec"
EVENT_PRIVILEGE_ESCALATION = "privilege_escalation"
EVENT_TRAFFIC_BURST = "traffic_burst"

# ─── Network Sensor ──────────────────────────────────────────────────
NETWORK_LISTEN_HOST = "127.0.0.1"
NETWORK_LISTEN_PORT_START = 8000
NETWORK_LISTEN_PORT_END = 8100
FLOW_BUCKET_SECONDS = 5          # Group packets into 5-second flows

# ─── Detection Thresholds ────────────────────────────────────────────
# Rule 1: Brute-force login
BRUTE_FORCE_THRESHOLD = 5        # failed logins from same IP
BRUTE_FORCE_WINDOW = 60          # seconds

# Rule 2: Fast port scan
FAST_SCAN_THRESHOLD = 10         # distinct ports
FAST_SCAN_WINDOW = 30            # seconds

# Rule 3: Slow port scan
SLOW_SCAN_THRESHOLD = 15         # distinct ports
SLOW_SCAN_WINDOW = 300           # seconds

# Rule 4: Login after scan (multi-source)
LOGIN_AFTER_SCAN_WINDOW = 120    # seconds

# Rule 5: Brute-force + success (multi-source)
BRUTE_SUCCESS_WINDOW = 120       # seconds

# Rule 6: Suspicious process after login (multi-source)
SUSPICIOUS_PROC_WINDOW = 60      # seconds

# ─── Anomaly Detection ───────────────────────────────────────────────
ANOMALY_Z_THRESHOLD = 3.0        # z-score threshold
ANOMALY_ROLLING_WINDOW = 100     # number of data points for rolling stats
ANOMALY_EPSILON = 1e-6           # prevent division by zero

# ─── Alert Manager ───────────────────────────────────────────────────
DEDUP_COOLDOWN_SECONDS = 60      # suppress same alert within this window
MAX_ALERTS_PER_MINUTE = 50       # rate limiting

# ─── Correlation Engine ──────────────────────────────────────────────
CORRELATION_WINDOW = 120         # default sliding window in seconds
EVENT_BUFFER_MAX_SIZE = 10000    # max events kept in memory

# ─── Experiment Settings ─────────────────────────────────────────────
BENIGN_BASELINE_DURATION = 10    # seconds of benign traffic before attack
EXPERIMENT_SETTLE_TIME = 5       # seconds to wait after attack for alerts

# ─── Suspicious Processes ────────────────────────────────────────────
SUSPICIOUS_PROCESSES = [
    "nc", "netcat", "ncat", "nmap", "wget", "curl",
    "python", "perl", "ruby", "bash", "sh", "powershell",
    "cmd.exe", "mimikatz", "crackmapexec", "hydra",
    "reverse_shell", "keylogger", "ransomware",
]

# ─── Logging ──────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
ALERT_LOG_FILE = "alerts.json"
HOST_LOG_FILE = "host_events.log"
RESULTS_DIR = "results"

# ─── Colors ───────────────────────────────────────────────────────────
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SEVERITY_COLORS = {
    SEVERITY_INFO: Colors.OKBLUE,
    SEVERITY_LOW: Colors.OKCYAN,
    SEVERITY_MEDIUM: Colors.WARNING,
    SEVERITY_HIGH: Colors.FAIL,
    SEVERITY_CRITICAL: Colors.BOLD + Colors.FAIL,
}
