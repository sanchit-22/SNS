#!/usr/bin/env python3
"""
tgs_node.py — Ticket Granting Server Node.

Runs 3 independent TGS processes (TGS1, TGS2, TGS3) on separate ports.
Each TGS independently signs Service Tickets using its own Schnorr key pair.
"""

import os
import sys
import json
import socket
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    mod_exp, schnorr_sign, schnorr_verify, verify_multi_signatures,
    aes_encrypt, aes_decrypt, generate_session_key,
    create_ticket_payload,
    send_message, recv_message,
    load_keys_from_file, is_ticket_expired,
    log_header, log_info, log_success, log_warning, log_error,
    log_crypto, log_network, log_separator, Colors
)

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")


class TicketGrantingServer:
    """A single Ticket Granting Server authority node."""

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

        # Load public config for AS public keys (to verify TGT signatures)
        public_path = os.path.join(CONFIG_DIR, "public_config.json")
        public_config = load_keys_from_file(public_path)
        self.as_public_keys = {
            k: int(v) for k, v in public_config["as_public_keys"].items()
        }

        log_crypto(self.authority_id, f"Loaded private key, p={self.p.bit_length()} bits")

    def handle_client(self, conn, addr):
        """Handle a service ticket request from a client."""
        try:
            log_network(self.authority_id, f"Connection from {addr}")

            request = recv_message(conn)
            if not request:
                log_error(self.authority_id, "Empty request received")
                return

            tgt_payload = request.get("tgt_payload")
            tgt_signatures = request.get("tgt_signatures", [])
            service_ticket_payload = request.get("service_ticket_payload")
            requested_service = request.get("requested_service", "SERVICE1")
            authenticator = request.get("authenticator", {})

            client_id = tgt_payload.get("client_id", "unknown")
            log_info(self.authority_id, f"Service ticket request from '{client_id}' for '{requested_service}'")

            # ── Verify TGT signatures (need ≥2 valid AS signatures) ──
            payload_json = json.dumps(tgt_payload, sort_keys=True)
            sigs = [(int(s["R"]), int(s["s"]), s["authority_id"]) for s in tgt_signatures]

            is_valid, valid_count, details = verify_multi_signatures(
                payload_json, sigs, self.as_public_keys, self.p, self.q, self.g, threshold=2
            )

            for auth_id, valid, reason in details:
                if valid:
                    log_success(self.authority_id, f"  AS sig from {auth_id}: {Colors.GREEN}VALID{Colors.RESET}")
                else:
                    log_error(self.authority_id, f"  AS sig from {auth_id}: {Colors.RED}INVALID ({reason}){Colors.RESET}")

            if not is_valid:
                log_error(self.authority_id, f"TGT verification FAILED ({valid_count}/2 valid sigs)")
                send_message(conn, {"status": "error", "message": f"TGT invalid: only {valid_count} valid signatures"})
                return

            log_success(self.authority_id, f"TGT verified: {valid_count} valid signatures ✔")

            # ── Check TGT expiry ──
            if is_ticket_expired(tgt_payload):
                log_error(self.authority_id, "TGT has expired")
                send_message(conn, {"status": "error", "message": "TGT expired"})
                return

            # ── Check key version ──
            if tgt_payload.get("key_version") != self.key_version:
                log_error(self.authority_id, f"Key version mismatch: ticket={tgt_payload.get('key_version')}, current={self.key_version}")
                send_message(conn, {"status": "error", "message": "Outdated key version"})
                return

            # ── Verify authenticator ──
            if authenticator.get("client_id") != client_id:
                log_error(self.authority_id, "Authenticator client_id mismatch")
                send_message(conn, {"status": "error", "message": "Authenticator mismatch"})
                return

            # ── Sign the service ticket payload provided by the client ──
            st_payload_json = json.dumps(service_ticket_payload, sort_keys=True)
            R, s, auth_id = schnorr_sign(
                st_payload_json, self.private_key, self.p, self.q, self.g, self.authority_id
            )
            log_crypto(self.authority_id, f"Service ticket signed for '{client_id}' → '{requested_service}'")

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
            log_success(self.authority_id, f"Service ticket signature sent to '{client_id}'")

        except Exception as e:
            log_error(self.authority_id, f"Error handling client: {e}")
            try:
                send_message(conn, {"status": "error", "message": str(e)})
            except:
                pass
        finally:
            conn.close()

    def start(self):
        """Start the TGS server."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)

        log_header(f"{self.authority_id} — Ticket Granting Server")
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
        """Stop the TGS server."""
        self.running = False
        try:
            self.server_socket.close()
        except:
            pass
        log_warning(self.authority_id, "Server stopped")


def run_all_tgs_nodes():
    """Start all 3 TGS nodes in separate threads."""
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    ports = load_keys_from_file(ports_path)

    servers = []
    threads = []

    for i in range(1, 4):
        auth_id = f"TGS{i}"
        port = ports[auth_id]
        server = TicketGrantingServer(auth_id, port)
        servers.append(server)

        t = threading.Thread(target=server.start, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)

    log_separator()
    log_success("TGS-CLUSTER", f"{Colors.BOLD}All 3 TGS nodes running: TGS1:{ports['TGS1']}, TGS2:{ports['TGS2']}, TGS3:{ports['TGS3']}{Colors.RESET}")
    log_separator()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_warning("TGS-CLUSTER", "Shutdown signal received...")
        for s in servers:
            s.stop()
        log_info("TGS-CLUSTER", "All TGS nodes stopped.")


if __name__ == "__main__":
    run_all_tgs_nodes()
