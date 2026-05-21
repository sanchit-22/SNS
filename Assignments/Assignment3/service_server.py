#!/usr/bin/env python3
"""
service_server.py — Service Server.

Receives service tickets from clients, verifies:
  - AES encryption integrity
  - At least 2 valid Schnorr signatures from TGS authorities
  - Ticket not expired
  - Key version not outdated
"""

import os
import sys
import json
import socket
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    schnorr_verify, verify_multi_signatures,
    aes_decrypt, is_ticket_expired,
    send_message, recv_message,
    load_keys_from_file,
    log_header, log_info, log_success, log_warning, log_error,
    log_crypto, log_network, log_separator, Colors
)

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")


class ServiceServer:
    """Service server that verifies service tickets and grants access."""

    def __init__(self, service_id="SERVICE1", port=7001):
        self.service_id = service_id
        self.port = port
        self.running = False

        # Load public config
        public_path = os.path.join(CONFIG_DIR, "public_config.json")
        public_config = load_keys_from_file(public_path)

        self.p = int(public_config["params"]["p"])
        self.q = int(public_config["params"]["q"])
        self.g = int(public_config["params"]["g"])
        self.key_version = int(public_config["params"]["key_version"])

        self.tgs_public_keys = {
            k: int(v) for k, v in public_config["tgs_public_keys"].items()
        }

        log_crypto(self.service_id, f"Loaded TGS public keys: {list(self.tgs_public_keys.keys())}")

    def handle_client(self, conn, addr):
        """Handle service access request from client."""
        try:
            log_network(self.service_id, f"Connection from {addr}")

            request = recv_message(conn)
            if not request:
                log_error(self.service_id, "Empty request received")
                return

            service_ticket_payload = request.get("service_ticket_payload")
            ticket_signatures = request.get("ticket_signatures", [])
            authenticator = request.get("authenticator", {})

            client_id = service_ticket_payload.get("client_id", "unknown")
            log_info(self.service_id, f"Access request from '{client_id}'")

            # ── Step 1: Verify service ID matches ──
            if service_ticket_payload.get("service_id") != self.service_id:
                log_error(self.service_id, f"Service ID mismatch: expected '{self.service_id}', got '{service_ticket_payload.get('service_id')}'")
                send_message(conn, {"status": "error", "message": "Service ID mismatch"})
                return

            # ── Step 2: Check ticket expiry ──
            if is_ticket_expired(service_ticket_payload):
                log_error(self.service_id, f"Ticket from '{client_id}' has EXPIRED")
                send_message(conn, {"status": "error", "message": "Ticket expired"})
                return
            log_success(self.service_id, f"Ticket not expired ✔")

            # ── Step 3: Check key version ──
            ticket_kv = service_ticket_payload.get("key_version")
            if ticket_kv != self.key_version:
                log_error(self.service_id, f"Outdated key version: ticket={ticket_kv}, current={self.key_version}")
                send_message(conn, {"status": "error", "message": "Outdated key version"})
                return
            log_success(self.service_id, f"Key version valid (v{self.key_version}) ✔")

            # ── Step 4: Verify TGS signatures (≥2 required) ──
            payload_json = json.dumps(service_ticket_payload, sort_keys=True)
            sigs = [(int(s["R"]), int(s["s"]), s["authority_id"]) for s in ticket_signatures]

            is_valid, valid_count, details = verify_multi_signatures(
                payload_json, sigs, self.tgs_public_keys, self.p, self.q, self.g, threshold=2
            )

            log_info(self.service_id, f"Signature verification results:")
            for auth_id, valid, reason in details:
                if valid:
                    log_success(self.service_id, f"  TGS sig from {auth_id}: {Colors.GREEN}VALID{Colors.RESET}")
                else:
                    log_error(self.service_id, f"  TGS sig from {auth_id}: {Colors.RED}INVALID ({reason}){Colors.RESET}")

            if not is_valid:
                log_error(self.service_id, f"ACCESS DENIED for '{client_id}': only {valid_count} valid signatures (need ≥2)")
                send_message(conn, {
                    "status": "error",
                    "message": f"Insufficient valid signatures: {valid_count}/2"
                })
                return

            # ── Step 5: Verify authenticator (timestamp match) ──
            auth_client_id = authenticator.get("client_id")
            if auth_client_id != client_id:
                log_error(self.service_id, f"Authenticator client ID mismatch: '{auth_client_id}' vs '{client_id}'")
                send_message(conn, {"status": "error", "message": "Authenticator mismatch"})
                return

            # ── ACCESS GRANTED ──
            log_separator()
            log_success(self.service_id,
                f"{Colors.BG_GREEN}{Colors.WHITE} ACCESS GRANTED {Colors.RESET} "
                f"{Colors.GREEN}Client '{client_id}' — {valid_count} valid TGS signatures{Colors.RESET}")
            log_separator()

            response = {
                "status": "ok",
                "message": f"Access granted to {self.service_id}",
                "server_timestamp": time.time(),
                "client_id": client_id
            }
            send_message(conn, response)

        except Exception as e:
            log_error(self.service_id, f"Error handling client: {e}")
            try:
                send_message(conn, {"status": "error", "message": str(e)})
            except:
                pass
        finally:
            conn.close()

    def start(self):
        """Start the service server."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)

        log_header(f"{self.service_id} — Service Server")
        log_network(self.service_id, f"Listening on port {self.port}")
        log_separator()

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                handler = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        """Stop the service server."""
        self.running = False
        try:
            self.server_socket.close()
        except:
            pass
        log_warning(self.service_id, "Server stopped")


def main():
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    ports = load_keys_from_file(ports_path)
    port = ports.get("SERVICE1", 7001)

    server = ServiceServer("SERVICE1", port)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        log_info("SERVICE1", "Service server stopped.")


if __name__ == "__main__":
    main()
