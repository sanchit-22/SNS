#!/usr/bin/env python3
"""
as_node.py — Authentication Server Node.

Runs 3 independent AS processes (AS1, AS2, AS3) on separate ports.
Each AS independently signs TGTs using its own Schnorr key pair.
"""

import os
import sys
import json
import socket
import threading
import hashlib
import time
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    mod_exp, schnorr_sign, schnorr_verify,
    aes_encrypt, generate_session_key,
    create_ticket_payload, serialize_ticket,
    send_message, recv_message, verify_user,
    load_keys_from_file,
    log_header, log_info, log_success, log_warning, log_error,
    log_crypto, log_network, log_separator, Colors
)

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")


class AuthenticationServer:
    """A single Authentication Server authority node."""

    def __init__(self, authority_id, port):
        self.authority_id = authority_id
        self.port = port
        self.running = False

        # Load private key config
        private_path = os.path.join(CONFIG_DIR, f"{authority_id.lower()}_private.json")
        config = load_keys_from_file(private_path)

        self.private_key = int(config["private_key"])
        self.public_key = int(config["public_key"])
        self.p = int(config["params"]["p"])
        self.q = int(config["params"]["q"])
        self.g = int(config["params"]["g"])
        self.key_version = int(config["params"]["key_version"])

        log_crypto(self.authority_id, f"Loaded private key, p={self.p.bit_length()} bits")

    def handle_client(self, conn, addr):
        """Handle a single client authentication request."""
        try:
            log_network(self.authority_id, f"Connection from {addr}")

            # Receive client request
            request = recv_message(conn)
            if not request:
                log_error(self.authority_id, "Empty request received")
                return

            username = request.get("username")
            password_hash = request.get("password_hash")
            tgt_payload = request.get("tgt_payload")  # Client-provided payload to sign

            log_info(self.authority_id, f"Auth request from user '{username}'")

            # Verify credentials
            if not verify_user(username, password_hash):
                log_error(self.authority_id, f"Authentication FAILED for user '{username}'")
                send_message(conn, {"status": "error", "message": "Invalid credentials"})
                return

            log_success(self.authority_id, f"User '{username}' authenticated successfully")

            # Verify the payload is well-formed and matches the requesting user
            if tgt_payload.get("client_id") != username:
                log_error(self.authority_id, f"Payload client_id mismatch")
                send_message(conn, {"status": "error", "message": "Payload client_id mismatch"})
                return

            # Sign the TGT payload provided by the client
            payload_json = json.dumps(tgt_payload, sort_keys=True)
            R, s, auth_id = schnorr_sign(payload_json, self.private_key, self.p, self.q, self.g, self.authority_id)
            log_crypto(self.authority_id, f"TGT signed for '{username}' (R={str(R)[:20]}...)")

            # Send response
            response = {
                "status": "ok",
                "signature": {
                    "R": str(R),
                    "s": str(s),
                    "authority_id": auth_id
                },
                "authority_id": self.authority_id
            }
            send_message(conn, response)
            log_success(self.authority_id, f"Signature sent to '{username}'")

        except Exception as e:
            log_error(self.authority_id, f"Error handling client: {e}")
            try:
                send_message(conn, {"status": "error", "message": str(e)})
            except:
                pass
        finally:
            conn.close()

    def start(self):
        """Start the AS server."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)

        log_header(f"{self.authority_id} — Authentication Server")
        log_network(self.authority_id, f"Listening on port {self.port}")
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
        """Stop the AS server."""
        self.running = False
        try:
            self.server_socket.close()
        except:
            pass
        log_warning(self.authority_id, "Server stopped")


def run_all_as_nodes():
    """Start all 3 AS nodes in separate threads."""
    # Load ports config
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    ports = load_keys_from_file(ports_path)

    servers = []
    threads = []

    for i in range(1, 4):
        auth_id = f"AS{i}"
        port = ports[auth_id]
        server = AuthenticationServer(auth_id, port)
        servers.append(server)

        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)

    log_separator()
    log_success("AS-CLUSTER", f"{Colors.BOLD}All 3 AS nodes running: AS1:{ports['AS1']}, AS2:{ports['AS2']}, AS3:{ports['AS3']}{Colors.RESET}")
    log_separator()

    # Wait for interrupt
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_warning("AS-CLUSTER", "Shutdown signal received...")
        for s in servers:
            s.stop()
        log_info("AS-CLUSTER", "All AS nodes stopped.")


if __name__ == "__main__":
    run_all_as_nodes()
