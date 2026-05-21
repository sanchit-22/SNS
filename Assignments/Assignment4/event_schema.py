"""
event_schema.py — Unified JSON-based event schema for the Multi-Source IDS.
All modules produce and consume events conforming to this schema.
"""

import uuid
import time
from datetime import datetime, timezone
from typing import Optional

import config


class Event:
    """
    Represents a single IDS event, used across all modules.
    """

    VALID_SOURCES = {config.SOURCE_NETWORK, config.SOURCE_HOST, config.SOURCE_CORRELATION}
    VALID_EVENT_TYPES = {
        config.EVENT_CONNECTION, config.EVENT_PORT_SCAN,
        config.EVENT_LOGIN_ATTEMPT, config.EVENT_LOGIN_SUCCESS,
        config.EVENT_PROCESS_EXEC, config.EVENT_PRIVILEGE_ESCALATION,
        config.EVENT_TRAFFIC_BURST,
    }
    VALID_SEVERITIES = set(config.SEVERITY_ORDER.keys())

    def __init__(
        self,
        source: str,
        event_type: str,
        severity: str = config.SEVERITY_INFO,
        src_ip: str = "",
        dst_ip: str = "127.0.0.1",
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "tcp",
        username: str = "",
        process_name: str = "",
        status: str = "",
        packet_count: int = 0,
        byte_count: int = 0,
        tags: Optional[list] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        is_malicious: bool = False,  # ground-truth label for metrics
    ):
        self.event_id = event_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.epoch = time.time()
        self.source = source
        self.event_type = event_type
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.username = username
        self.process_name = process_name
        self.status = status
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.tags = tags or []
        self.is_malicious = is_malicious  # ground truth

    def validate(self) -> bool:
        """Strictly validate that the event conforms to the schema."""
        errors = []

        if self.source not in self.VALID_SOURCES:
            errors.append(f"Invalid source: {self.source}")
        if self.event_type not in self.VALID_EVENT_TYPES:
            errors.append(f"Invalid event_type: {self.event_type}")
        if self.severity not in self.VALID_SEVERITIES:
            errors.append(f"Invalid severity: {self.severity}")
        if not isinstance(self.tags, list):
            errors.append(f"Tags must be a list, got: {type(self.tags)}")
        if not self.event_id:
            errors.append("event_id is required")
        if not self.timestamp:
            errors.append("timestamp is required")

        if errors:
            raise ValueError(f"Event validation failed: {'; '.join(errors)}")
        return True

    def to_dict(self) -> dict:
        """Serialize event to JSON-compatible dict."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": {
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
                "username": self.username,
                "process_name": self.process_name,
                "status": self.status,
                "packet_count": self.packet_count,
                "byte_count": self.byte_count,
            },
            "tags": self.tags,
            "is_malicious": self.is_malicious,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        """Deserialize event from dict."""
        details = data.get("details", {})
        event = cls(
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp"),
            source=data["source"],
            event_type=data["event_type"],
            severity=data.get("severity", config.SEVERITY_INFO),
            src_ip=details.get("src_ip", ""),
            dst_ip=details.get("dst_ip", "127.0.0.1"),
            src_port=details.get("src_port", 0),
            dst_port=details.get("dst_port", 0),
            protocol=details.get("protocol", "tcp"),
            username=details.get("username", ""),
            process_name=details.get("process_name", ""),
            status=details.get("status", ""),
            packet_count=details.get("packet_count", 0),
            byte_count=details.get("byte_count", 0),
            tags=data.get("tags", []),
            is_malicious=data.get("is_malicious", False),
        )
        if "epoch" in data:
            event.epoch = data["epoch"]
        return event

    def __repr__(self):
        return (
            f"Event(id={self.event_id[:8]}, type={self.event_type}, "
            f"src={self.src_ip}, severity={self.severity}, tags={self.tags})"
        )


def create_network_event(
    src_ip: str,
    dst_port: int,
    protocol: str = "tcp",
    packet_count: int = 1,
    byte_count: int = 64,
    is_malicious: bool = False,
    tags: Optional[list] = None,
) -> Event:
    """Factory: create a network connection event."""
    return Event(
        source=config.SOURCE_NETWORK,
        event_type=config.EVENT_CONNECTION,
        severity=config.SEVERITY_INFO,
        src_ip=src_ip,
        dst_ip="127.0.0.1",
        dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        is_malicious=is_malicious,
        tags=tags or [],
    )


def create_login_event(
    src_ip: str,
    username: str,
    success: bool,
    is_malicious: bool = False,
    tags: Optional[list] = None,
) -> Event:
    """Factory: create a login attempt event (host sensor)."""
    return Event(
        source=config.SOURCE_HOST,
        event_type=config.EVENT_LOGIN_SUCCESS if success else config.EVENT_LOGIN_ATTEMPT,
        severity=config.SEVERITY_INFO if success else config.SEVERITY_LOW,
        src_ip=src_ip,
        username=username,
        status="success" if success else "failure",
        is_malicious=is_malicious,
        tags=tags or [],
    )


def create_process_event(
    src_ip: str,
    username: str,
    process_name: str,
    is_malicious: bool = False,
    tags: Optional[list] = None,
) -> Event:
    """Factory: create a process execution event (host sensor)."""
    suspicious = process_name.lower() in [p.lower() for p in config.SUSPICIOUS_PROCESSES]
    return Event(
        source=config.SOURCE_HOST,
        event_type=config.EVENT_PROCESS_EXEC,
        severity=config.SEVERITY_MEDIUM if suspicious else config.SEVERITY_INFO,
        src_ip=src_ip,
        username=username,
        process_name=process_name,
        is_malicious=is_malicious,
        tags=(tags or []) + (["suspicious_process"] if suspicious else []),
    )
