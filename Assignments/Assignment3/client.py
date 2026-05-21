#!/usr/bin/env python3
"""
client.py — Kerberos Client.

Implements the full 3-phase authentication flow:
  Phase 1: Distributed AS Exchange — Contact AS1-3, collect ≥2 Schnorr-signed TGTs
  Phase 2: Distributed TGS Exchange — Contact TGS1-3, collect ≥2 signed service tickets
  Phase 3: Service Authentication — Present ticket to service server
"""

import os
import sys
import json
import socket
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_verify, verify_multi_signatures,
    aes_encrypt, aes_decrypt, generate_session_key,
    create_ticket_payload, load_keys_from_file,
    send_message, recv_message,
    log_header, log_info, log_success, log_warning, log_error,
    log_crypto, log_network, log_separator, Colors
)

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")


class KerberosClient:
    """Client that authenticates through the distributed Kerberos system."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Load public config
        public_path = os.path.join(CONFIG_DIR, "public_config.json")
        public_config = load_keys_from_file(public_path)

        self.p = int(public_config["params"]["p"])
        self.q = int(public_config["params"]["q"])
        self.g = int(public_config["params"]["g"])
        self.key_version = int(public_config["params"]["key_version"])

        self.as_public_keys = {k: int(v) for k, v in public_config["as_public_keys"].items()}
        self.tgs_public_keys = {k: int(v) for k, v in public_config["tgs_public_keys"].items()}

        # Load ports
        ports_path = os.path.join(CONFIG_DIR, "ports.json")
        self.ports = load_keys_from_file(ports_path)

        # State
        self.tgt_payload = None
        self.tgt_signatures = []
        self.tgt_session_key = None
        self.service_ticket_payload = None
        self.service_ticket_signatures = []
        self.service_session_key = None

    def _connect(self, port):
        """Create a socket connection to localhost:port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', port))
        return sock

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 1: Distributed AS Exchange
    # ═══════════════════════════════════════════════════════════════════════

    def phase1_as_exchange(self):
        """Contact all 3 AS nodes and collect TGT signatures."""
        log_header("PHASE 1: Distributed AS Exchange")
        log_info("CLIENT", f"User: {Colors.BOLD}{self.username}{Colors.RESET}")
        log_separator()

        # Client generates the TGT payload locally
        # This ensures all AS nodes sign the SAME payload
        tgt_session_key = generate_session_key()
        tgt_payload = create_ticket_payload(
            client_id=self.username,
            service_id="TGS",
            session_key=tgt_session_key,
            lifetime=300,
            key_version=self.key_version
        )

        log_crypto("CLIENT", "Generated TGT payload with session key")

        collected_signatures = []

        for i in range(1, 4):
            auth_id = f"AS{i}"
            port = self.ports[auth_id]

            try:
                log_network("CLIENT", f"Contacting {auth_id} on port {port}...")

                sock = self._connect(port)
                request = {
                    "username": self.username,
                    "password_hash": self.password_hash,
                    "tgt_payload": tgt_payload
                }
                send_message(sock, request)
                response = recv_message(sock)
                sock.close()

                if not response or response.get("status") != "ok":
                    error_msg = response.get("message", "Unknown error") if response else "No response"
                    log_error("CLIENT", f"{auth_id}: {error_msg}")
                    continue

                # Store signature
                sig = response["signature"]
                collected_signatures.append(sig)

                # Verify signature locally
                payload_json = json.dumps(tgt_payload, sort_keys=True)
                R, s = int(sig["R"]), int(sig["s"])
                y = self.as_public_keys[auth_id]
                valid = schnorr_verify(payload_json, R, s, y, self.p, self.q, self.g, auth_id)

                if valid:
                    log_success("CLIENT", f"{auth_id}: Signature {Colors.GREEN}VALID{Colors.RESET} ✔")
                else:
                    log_error("CLIENT", f"{auth_id}: Signature {Colors.RED}INVALID{Colors.RESET} ✖")

            except ConnectionRefusedError:
                log_warning("CLIENT", f"{auth_id}: Server OFFLINE (connection refused)")
            except Exception as e:
                log_error("CLIENT", f"{auth_id}: Error - {e}")

        log_separator()

        if len(collected_signatures) >= 2:
            self.tgt_payload = tgt_payload
            self.tgt_signatures = collected_signatures
            self.tgt_session_key = tgt_session_key
            log_success("CLIENT",
                f"{Colors.BOLD}Phase 1 COMPLETE: Collected {len(collected_signatures)} AS signatures ✔{Colors.RESET}")
            return True
        else:
            log_error("CLIENT",
                f"Phase 1 FAILED: Only {len(collected_signatures)} signatures collected (need ≥2)")
            return False

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 2: Distributed TGS Exchange
    # ═══════════════════════════════════════════════════════════════════════

    def phase2_tgs_exchange(self, requested_service="SERVICE1"):
        """Contact all 3 TGS nodes with TGT and collect service ticket signatures."""
        log_header("PHASE 2: Distributed TGS Exchange")
        log_info("CLIENT", f"Requesting service ticket for '{requested_service}'")
        log_separator()

        if not self.tgt_payload or len(self.tgt_signatures) < 2:
            log_error("CLIENT", "No valid TGT available. Run Phase 1 first.")
            return False

        # Client generates the service ticket payload locally
        service_session_key = generate_session_key()
        service_ticket_payload = create_ticket_payload(
            client_id=self.username,
            service_id=requested_service,
            session_key=service_session_key,
            lifetime=300,
            key_version=self.key_version
        )

        # Encrypt the TGT session key for verification by TGS
        encrypted_tgt_session_key = aes_encrypt(
            self.tgt_session_key,
            hashlib.sha256(self.password_hash.encode()).digest()
        )

        log_crypto("CLIENT", "Generated service ticket payload with session key")

        collected_signatures = []

        for i in range(1, 4):
            auth_id = f"TGS{i}"
            port = self.ports[auth_id]

            try:
                log_network("CLIENT", f"Contacting {auth_id} on port {port}...")

                sock = self._connect(port)
                request = {
                    "tgt_payload": self.tgt_payload,
                    "tgt_signatures": self.tgt_signatures,
                    "service_ticket_payload": service_ticket_payload,
                    "requested_service": requested_service,
                    "authenticator": {
                        "client_id": self.username,
                        "timestamp": time.time()
                    }
                }
                send_message(sock, request)
                response = recv_message(sock)
                sock.close()

                if not response or response.get("status") != "ok":
                    error_msg = response.get("message", "Unknown error") if response else "No response"
                    log_error("CLIENT", f"{auth_id}: {error_msg}")
                    continue

                sig = response["signature"]
                collected_signatures.append(sig)

                # Verify signature locally
                st_payload_json = json.dumps(service_ticket_payload, sort_keys=True)
                R, s = int(sig["R"]), int(sig["s"])
                y = self.tgs_public_keys[auth_id]
                valid = schnorr_verify(st_payload_json, R, s, y, self.p, self.q, self.g, auth_id)

                if valid:
                    log_success("CLIENT", f"{auth_id}: Signature {Colors.GREEN}VALID{Colors.RESET} ✔")
                else:
                    log_error("CLIENT", f"{auth_id}: Signature {Colors.RED}INVALID{Colors.RESET} ✖")

            except ConnectionRefusedError:
                log_warning("CLIENT", f"{auth_id}: Server OFFLINE (connection refused)")
            except Exception as e:
                log_error("CLIENT", f"{auth_id}: Error - {e}")

        log_separator()

        if len(collected_signatures) >= 2:
            self.service_ticket_payload = service_ticket_payload
            self.service_ticket_signatures = collected_signatures
            self.service_session_key = service_session_key
            log_success("CLIENT",
                f"{Colors.BOLD}Phase 2 COMPLETE: Collected {len(collected_signatures)} TGS signatures ✔{Colors.RESET}")
            return True
        else:
            log_error("CLIENT",
                f"Phase 2 FAILED: Only {len(collected_signatures)} signatures collected (need ≥2)")
            return False

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 3: Service Authentication
    # ═══════════════════════════════════════════════════════════════════════

    def phase3_service_auth(self, service_id="SERVICE1"):
        """Present service ticket to the service server."""
        log_header("PHASE 3: Service Authentication")
        log_info("CLIENT", f"Accessing service '{service_id}'")
        log_separator()

        if not self.service_ticket_payload or len(self.service_ticket_signatures) < 2:
            log_error("CLIENT", "No valid service ticket available. Run Phase 2 first.")
            return False

        port = self.ports.get(service_id, 7001)

        try:
            log_network("CLIENT", f"Connecting to {service_id} on port {port}...")

            sock = self._connect(port)
            request = {
                "service_ticket_payload": self.service_ticket_payload,
                "ticket_signatures": self.service_ticket_signatures,
                "authenticator": {
                    "client_id": self.username,
                    "timestamp": time.time()
                }
            }
            send_message(sock, request)
            response = recv_message(sock)
            sock.close()

            if not response:
                log_error("CLIENT", "No response from service server")
                return False

            if response.get("status") == "ok":
                log_separator()
                log_success("CLIENT",
                    f"{Colors.BG_GREEN}{Colors.WHITE} SERVICE ACCESS GRANTED {Colors.RESET} "
                    f"{Colors.GREEN}{response.get('message', '')}{Colors.RESET}")
                log_separator()
                return True
            else:
                log_error("CLIENT",
                    f"{Colors.BG_RED}{Colors.WHITE} SERVICE ACCESS DENIED {Colors.RESET} "
                    f"{Colors.RED}{response.get('message', '')}{Colors.RESET}")
                return False

        except ConnectionRefusedError:
            log_error("CLIENT", f"{service_id}: Connection refused")
            return False
        except Exception as e:
            log_error("CLIENT", f"Error: {e}")
            return False


def main():
    """Run the full Kerberos authentication flow."""
    log_header("KERBEROS MULTI-SIGNATURE CLIENT")
    print(f"  {Colors.CYAN}Architecture:{Colors.RESET} 2-of-3 Schnorr Multi-Signatures")
    print(f"  {Colors.CYAN}AS Cluster:{Colors.RESET}   AS1, AS2, AS3")
    print(f"  {Colors.CYAN}TGS Cluster:{Colors.RESET}  TGS1, TGS2, TGS3")
    print(f"  {Colors.CYAN}Service:{Colors.RESET}      SERVICE1")
    print()
    log_separator()

    # Create client for user 'alice'
    client = KerberosClient("alice", "password_alice")

    # Phase 1: Get TGT from AS cluster
    if not client.phase1_as_exchange():
        log_error("CLIENT", "Authentication failed at Phase 1")
        sys.exit(1)

    time.sleep(0.5)

    # Phase 2: Get service ticket from TGS cluster
    if not client.phase2_tgs_exchange("SERVICE1"):
        log_error("CLIENT", "Authentication failed at Phase 2")
        sys.exit(1)

    time.sleep(0.5)

    # Phase 3: Access service
    if not client.phase3_service_auth("SERVICE1"):
        log_error("CLIENT", "Authentication failed at Phase 3")
        sys.exit(1)

    log_header("AUTHENTICATION FLOW COMPLETE")
    log_success("CLIENT", f"{Colors.BOLD}All 3 phases completed successfully!{Colors.RESET}")


if __name__ == "__main__":
    main()
