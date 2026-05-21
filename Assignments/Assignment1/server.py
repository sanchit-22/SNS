"""
server.py
=========
Multi-client secure communication server with symmetric key cryptography.

Features:
- Handles multiple simultaneous clients
- Maintains separate session state per client
- Aggregates numeric data from all clients
- Implements stateful protocol with key evolution
- Detects and handles all attack scenarios

Author: CS5.470 Lab Assignment 1
Date: January 2026
"""

import socket
import threading
import struct
import os
import json
from typing import Dict, List
from protocol_fsm import (
    SessionState, Opcode, Direction, ProtocolPhase,
    construct_message, parse_message, check_protocol_consistency,
    create_error_message, create_terminate_message,
    HEADER_SIZE, HMAC_SIZE
)


# ============================================================================
# Server Configuration
# ============================================================================

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
MAX_CLIENTS = 10

# Pre-shared master keys for each client (in production, load from secure storage)
CLIENT_MASTER_KEYS = {
    1: bytes.fromhex('0123456789abcdef0123456789abcdef'),
    2: bytes.fromhex('fedcba9876543210fedcba9876543210'),
    3: bytes.fromhex('11112222333344445555666677778888'),
    4: bytes.fromhex('aaaabbbbccccddddeeeeffffaaaabbbb'),
    5: bytes.fromhex('00001111222233334444555566667777'),
}


# ============================================================================
# Server Class
# ============================================================================

class SecureServer:
    """
    Secure multi-client server implementing stateful symmetric-key protocol.
    """
    
    def __init__(self, host: str, port: int):
        """
        Initialize the server.
        
        Args:
            host: Server IP address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.sessions: Dict[int, SessionState] = {}  # client_id -> SessionState
        self.round_data: Dict[int, Dict[int, float]] = {}  # round -> {client_id -> data_value}
        self.lock = threading.Lock()  # Thread-safe access to shared data
        self.running = False
        self.server_socket = None
        self.client_sockets: Dict[int, socket.socket] = {}  # client_id -> socket for graceful shutdown
        
        print(f"[SERVER] Initialized on {host}:{port}")
    
    def start(self):
        """Start the server and listen for client connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(MAX_CLIENTS)
        self.running = True
        
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        print(f"[SERVER] Waiting for clients... (Press Ctrl+C to stop)")
        
        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"\n[SERVER] New connection from {client_address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except OSError:
                    break
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server and close all client connections"""
        self.running = False
        
        # Send shutdown signal to all clients and close their sockets
        with self.lock:
            for client_id, client_socket in list(self.client_sockets.items()):
                try:
                    print(f"[SERVER] Sending shutdown signal to Client {client_id}")
                    # Send a TERMINATE message to client
                    session = self.sessions.get(client_id)
                    if session:
                        terminate_msg = create_terminate_message(
                            client_id,
                            session.round,
                            "Server shutting down",
                            session.s2c_enc_key,
                            session.s2c_mac_key
                        )
                        try:
                            # Send message length and message
                            msg_length = struct.pack('!I', len(terminate_msg))
                            client_socket.sendall(msg_length + terminate_msg)
                        except:
                            pass
                    
                    # Close the socket
                    print(f"[SERVER] Closing connection to Client {client_id}")
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()
                except Exception as e:
                    # Socket might already be closed
                    try:
                        client_socket.close()
                    except:
                        pass
            self.client_sockets.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[SERVER] Server stopped")
        print("[SERVER] All client connections closed")
    
    def handle_client(self, client_socket: socket.socket, client_address):
        """
        Handle a single client connection.
        
        Args:
            client_socket: Client socket
            client_address: Client address tuple
        """
        client_id = None
        session = None
        
        try:
            while True:
                # Receive message length first (4 bytes)
                length_data = self.recv_exact(client_socket, 4)
                if not length_data:
                    break
                
                message_length = struct.unpack('!I', length_data)[0]
                
                # Receive the actual message
                message = self.recv_exact(client_socket, message_length)
                if not message:
                    break
                
                # Extract client_id from header to identify session
                if len(message) >= 2:
                    temp_client_id = message[1]
                    
                    # If this is a new client, create session
                    if temp_client_id not in self.sessions:
                        with self.lock:
                            if temp_client_id not in CLIENT_MASTER_KEYS:
                                print(f"[SERVER] \033[91mERROR: Unknown client ID: {temp_client_id}\033[0m")
                                # Send error and close connection
                                error_msg = f"Client ID {temp_client_id} not registered"
                                client_socket.sendall(error_msg.encode('utf-8'))
                                break
                            
                            master_key = CLIENT_MASTER_KEYS[temp_client_id]
                            self.sessions[temp_client_id] = SessionState(temp_client_id, master_key)
                            self.client_sockets[temp_client_id] = client_socket  # Store socket for shutdown
                            print(f"[SERVER] Created session for Client {temp_client_id}")
                    else:
                        # Check if this is a duplicate connection (same client_id, different socket)
                        with self.lock:
                            if temp_client_id in self.client_sockets and self.client_sockets[temp_client_id] != client_socket:
                                print(f"[SERVER] \033[91mERROR: Client ID {temp_client_id} already connected!\033[0m")
                                error_msg = f"Client ID {temp_client_id} is already active. Cannot have duplicate connections."
                                try:
                                    client_socket.sendall(error_msg.encode('utf-8'))
                                except:
                                    pass
                                break
                    
                    client_id = temp_client_id
                    session = self.sessions[client_id]
                
                # Process the message
                response = self.process_message(message, session)
                
                if response:
                    # Send response length first
                    response_length = struct.pack('!I', len(response))
                    client_socket.sendall(response_length + response)
                
                # Check if session terminated
                if session and session.is_terminated():
                    print(f"[SERVER] Session terminated for Client {client_id}")
                    break
                    
        except Exception as e:
            print(f"[SERVER] Error handling client {client_id}: {e}")
            if session:
                session.terminate()
        finally:
            client_socket.close()
            if client_id:
                with self.lock:
                    # Release client ID so it can be reused
                    if client_id in self.sessions:
                        del self.sessions[client_id]
                        print(f"[SERVER] Released session for Client {client_id}")
                    if client_id in self.client_sockets:
                        del self.client_sockets[client_id]
                print(f"[SERVER] Client {client_id} disconnected from {client_address}")
                print(f"[SERVER] Client ID {client_id} is now available for reuse")
    
    def recv_exact(self, sock: socket.socket, n: int) -> bytes:
        """
        Receive exactly n bytes from socket.
        
        Args:
            sock: Socket to receive from
            n: Number of bytes to receive
        
        Returns:
            Received bytes, or empty bytes if connection closed
        """
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return b''
            data += chunk
        return data
    
    def process_message(self, message: bytes, session: SessionState) -> bytes:
        """
        Process a received message and generate response.
        
        Implements the protocol state machine:
        1. Validate message structure
        2. Check protocol consistency (round, phase, opcode)
        3. Verify HMAC
        4. Decrypt and process payload
        5. Update session state
        6. Generate response
        
        Args:
            message: Received message bytes
            session: Client session state
        
        Returns:
            Response message bytes, or None if no response needed
        """
        client_id = session.client_id
        
        try:
            # Extract opcode and round from header (minimal parsing for consistency check)
            if len(message) < HEADER_SIZE:
                raise ValueError("Message too short")
            
            opcode = message[0]
            round_num = struct.unpack('!I', message[2:6])[0]
            
            # Print opcode in GREEN for visibility
            print(f"[SERVER] \033[92mOPCODE: {opcode}\033[0m from Client {client_id} (Round {round_num})")
            
            # Check protocol consistency
            error_msg = check_protocol_consistency(session, opcode, round_num, is_server=True)
            if error_msg:
                print(f"[SERVER] Protocol error for Client {client_id}: {error_msg}")
                session.terminate()
                return self.send_error(session, f"Protocol error: {error_msg}")
            
            # Parse and decrypt message
            try:
                parsed_opcode, parsed_client_id, parsed_round, plaintext = parse_message(
                    message,
                    session.round,
                    Direction.CLIENT_TO_SERVER,
                    session.c2s_enc_key,
                    session.c2s_mac_key
                )
            except ValueError as e:
                print(f"[SERVER] Message validation failed for Client {client_id}: {e}")
                session.terminate()
                return self.send_error(session, f"Validation failed: {e}")
            
            # Process based on opcode
            if opcode == Opcode.CLIENT_HELLO:
                return self.handle_client_hello(session, plaintext)
            
            elif opcode == Opcode.CLIENT_DATA:
                return self.handle_client_data(session, plaintext, message)
            
            else:
                print(f"[SERVER] Unexpected opcode {opcode} from Client {client_id}")
                session.terminate()
                return self.send_error(session, f"Unexpected opcode: {opcode}")
        
        except Exception as e:
            print(f"[SERVER] Exception processing message from Client {client_id}: {e}")
            session.terminate()
            if session:
                return self.send_terminate(session, f"Server error: {e}")
            return None
    
    def handle_client_hello(self, session: SessionState, plaintext: bytes) -> bytes:
        """
        Handle CLIENT_HELLO message.
        
        Protocol:
        1. Receive CLIENT_HELLO with client info
        2. Send SERVER_CHALLENGE with random nonce
        3. Transition to ACTIVE phase
        4. Evolve keys
        
        Args:
            session: Client session
            plaintext: Decrypted payload
        
        Returns:
            SERVER_CHALLENGE response
        """
        client_id = session.client_id
        
        try:
            # Parse client hello payload
            client_info = plaintext.decode('utf-8')
            print(f"[SERVER] \033[92m[OPCODE 10: CLIENT_HELLO]\033[0m from Client {client_id}: {client_info}")
            
            # Generate server challenge (random nonce)
            nonce = os.urandom(16)
            challenge_data = {
                'status': 'OK',
                'challenge': nonce.hex(),
                'message': 'Welcome! Please send your data.'
            }
            challenge_json = json.dumps(challenge_data).encode('utf-8')
            
            # Build SERVER_CHALLENGE message
            response = construct_message(
                Opcode.SERVER_CHALLENGE,
                client_id,
                session.round,
                Direction.SERVER_TO_CLIENT,
                challenge_json,
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            # Evolve keys after successful exchange
            # C2S keys: use ciphertext and nonce from CLIENT_HELLO
            # Note: In real implementation, extract actual ciphertext from original message
            # For simplicity, using plaintext as proxy
            session.evolve_keys_c2s(plaintext, nonce)
            
            # S2C keys: use challenge data and status
            session.evolve_keys_s2c(challenge_json, b'OK')
            
            # Transition to ACTIVE phase and advance round
            session.activate()
            session.advance_round()
            
            print(f"[SERVER] \033[92m[OPCODE 20: SERVER_CHALLENGE]\033[0m sent to Client {client_id}, now in ACTIVE phase")
            return response
            
        except Exception as e:
            print(f"[SERVER] Error in CLIENT_HELLO handler: {e}")
            session.terminate()
            return self.send_error(session, f"Error processing CLIENT_HELLO: {e}")
    
    def handle_client_data(self, session: SessionState, plaintext: bytes, 
                          original_message: bytes) -> bytes:
        """
        Handle CLIENT_DATA message.
        
        Protocol:
        1. Receive CLIENT_DATA with numeric data
        2. Store data for aggregation
        3. Compute aggregate across all active clients
        4. Send SERVER_AGGR_RESPONSE with aggregate
        5. Evolve keys
        
        Args:
            session: Client session
            plaintext: Decrypted payload
            original_message: Original encrypted message (for key evolution)
        
        Returns:
            SERVER_AGGR_RESPONSE message
        """
        client_id = session.client_id
        
        try:
            # Parse client data
            data_json = json.loads(plaintext.decode('utf-8'))
            data_value = float(data_json.get('data', 0))
            current_round = session.round
            
            # Store data per round
            with self.lock:
                if current_round not in self.round_data:
                    self.round_data[current_round] = {}
                self.round_data[current_round][client_id] = data_value
            
            print(f"[SERVER] \033[92m[OPCODE 30: CLIENT_DATA]\033[0m from Client {client_id}: {data_value} (Round {current_round})")
            
            # Compute aggregate for THIS ROUND ONLY (among all clients in this round)
            with self.lock:
                aggregate = 0.0
                count = 0
                if current_round in self.round_data:
                    for cid, value in self.round_data[current_round].items():
                        aggregate += value
                        count += 1
            
            # Generate nonce for key evolution (must be shared with client)
            nonce = os.urandom(16)
            
            # Prepare response
            response_data = {
                'status': 'OK',
                'aggregate_sum': aggregate,
                'data_count': count,
                'your_contribution': data_value,
                'round': current_round,
                'nonce': nonce.hex()  # Include nonce so client can evolve keys identically
            }
            response_json = json.dumps(response_data).encode('utf-8')
            
            # Build SERVER_AGGR_RESPONSE
            response = construct_message(
                Opcode.SERVER_AGGR_RESPONSE,
                client_id,
                session.round,
                Direction.SERVER_TO_CLIENT,
                response_json,
                session.s2c_enc_key,
                session.s2c_mac_key
            )
            
            # Evolve keys after successful exchange
            # C2S keys: use ciphertext from CLIENT_DATA and shared nonce
            ciphertext = original_message[HEADER_SIZE:-HMAC_SIZE]
            session.evolve_keys_c2s(ciphertext, nonce)
            
            # S2C keys: use aggregated data and status
            session.evolve_keys_s2c(response_json, b'OK')
            
            # Advance round - server advances after sending response
            # Client will advance after receiving response
            # Both will be in sync for next exchange
            session.advance_round()
            
            print(f"[SERVER] \033[92m[OPCODE 40: SERVER_AGGR_RESPONSE]\033[0m sent to Client {client_id}: "
                  f"aggregate={aggregate}, count={count}, round={current_round}")
            print(f"[SERVER] Client {client_id} session advanced to Round {session.round}")
            
            return response
            
        except Exception as e:
            print(f"[SERVER] Error in CLIENT_DATA handler: {e}")
            session.terminate()
            return self.send_error(session, f"Error processing CLIENT_DATA: {e}")
    
    def send_error(self, session: SessionState, error_msg: str) -> bytes:
        """
        Send KEY_DESYNC_ERROR message to client.
        
        Args:
            session: Client session
            error_msg: Error message
        
        Returns:
            Error message bytes
        """
        print(f"[SERVER] Sending error to Client {session.client_id}: {error_msg}")
        return create_error_message(
            session.client_id,
            session.round,
            error_msg,
            session.s2c_enc_key,
            session.s2c_mac_key
        )
    
    def send_terminate(self, session: SessionState, reason: str) -> bytes:
        """
        Send TERMINATE message to client.
        
        Args:
            session: Client session
            reason: Termination reason
        
        Returns:
            Terminate message bytes
        """
        print(f"[SERVER] Terminating Client {session.client_id}: {reason}")
        session.terminate()
        return create_terminate_message(
            session.client_id,
            session.round,
            reason,
            session.s2c_enc_key,
            session.s2c_mac_key,
            Direction.SERVER_TO_CLIENT
        )


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main server entry point"""
    print("=" * 70)
    print("  SECURE MULTI-CLIENT COMMUNICATION SERVER")
    print("  CS5.470 Lab Assignment 1")
    print("=" * 70)
    print()
    
    # Create and start server
    server = SecureServer(SERVER_HOST, SERVER_PORT)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Interrupted by user")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
