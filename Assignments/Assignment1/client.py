"""
client.py
=========
Secure client implementing stateful symmetric-key protocol with real-time interactive communication.

Features:
- Connects to server and authenticates
- Maintains session state with key evolution
- Sends data in real-time (interactive mode)
- Displays detailed encryption/decryption information
- Shows key evolution at each step

Author: CS5.470 Lab Assignment 1
Date: January 2026
"""

import socket
import struct
import json
import time
import sys
from protocol_fsm import (
    SessionState, Opcode, Direction, ProtocolPhase,
    construct_message, parse_message, check_protocol_consistency,
    create_terminate_message,
    HEADER_SIZE, HMAC_SIZE
)


# ============================================================================
# Client Configuration
# ============================================================================

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999


# ============================================================================
# Utility Functions for Display
# ============================================================================

def print_separator(char='=', length=80):
    """Print a separator line"""
    print(char * length)


def print_header(text):
    """Print a section header"""
    print_separator()
    print(f"  {text}")
    print_separator()


def print_encryption_details(stage, **kwargs):
    """Print detailed encryption information"""
    print(f"\n{'─'*80}")
    print(f"🔐 ENCRYPTION DETAILS - {stage}")
    print(f"{'─'*80}")
    for key, value in kwargs.items():
        if isinstance(value, bytes):
            if len(value) <= 32:
                print(f"  {key:20s}: {value.hex()}")
            else:
                print(f"  {key:20s}: {value.hex()[:64]}... ({len(value)} bytes)")
        else:
            print(f"  {key:20s}: {value}")
    print(f"{'─'*80}")


def print_key_info(session, label="Current Keys"):
    """Print current key information"""
    print(f"\n{'─'*80}")
    print(f"🔑 KEY STATE - {label}")
    print(f"{'─'*80}")
    print(f"  Round Number        : {session.round}")
    print(f"  Protocol Phase      : {session.phase.name}")
    print(f"  C2S Encryption Key  : {session.c2s_enc_key.hex()}")
    print(f"  C2S MAC Key         : {session.c2s_mac_key.hex()}")
    print(f"  S2C Encryption Key  : {session.s2c_enc_key.hex()}")
    print(f"  S2C MAC Key         : {session.s2c_mac_key.hex()}")
    print(f"{'─'*80}")


# ============================================================================
# Client Class
# ============================================================================

class SecureClient:
    """
    Secure client implementing stateful symmetric-key protocol with real-time communication.
    """
    
    def __init__(self, client_id: int, master_key: bytes, server_host: str, server_port: int):
        """
        Initialize the client.
        
        Args:
            client_id: Unique client identifier
            master_key: Pre-shared symmetric master key
            server_host: Server IP address
            server_port: Server port
        """
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.session = SessionState(client_id, master_key)
        self.socket = None
        self.connected = False
        
        print(f"\n[CLIENT {client_id}] Initialized with master key: {master_key.hex()}")
        print_key_info(self.session, "Initial Keys (Derived from Master Key)")
    
    def connect(self) -> bool:
        """
        Connect to the server.
        
        Returns:
            True if connected successfully, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            print(f"\n✓ [CLIENT {self.client_id}] Connected to {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        print(f"\n[CLIENT {self.client_id}] Disconnected")
    
    def send_message(self, message: bytes):
        """
        Send a message to the server.
        
        Protocol: Send message length (4 bytes) followed by message.
        
        Args:
            message: Message bytes to send
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")
        
        # Send length prefix
        length = struct.pack('!I', len(message))
        self.socket.sendall(length + message)
    
    def receive_message(self) -> bytes:
        """
        Receive a message from the server.
        
        Protocol: Receive message length (4 bytes) then message.
        
        Returns:
            Received message bytes
        
        Raises:
            ConnectionError: If connection is closed by server
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")
        
        # Receive length prefix
        length_data = self.recv_exact(4)
        if not length_data:
            raise ConnectionError("Server closed connection")
        
        message_length = struct.unpack('!I', length_data)[0]
        
        # Receive message
        message = self.recv_exact(message_length)
        if not message:
            raise ConnectionError("Server closed connection")
        
        return message
    
    def recv_exact(self, n: int) -> bytes:
        """
        Receive exactly n bytes from socket.
        
        Args:
            n: Number of bytes to receive
        
        Returns:
            Received bytes
        """
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return b''
            data += chunk
        return data
    
    def send_client_hello(self) -> bool:
        """
        Send CLIENT_HELLO to initiate protocol.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            print_header(f"CLIENT {self.client_id} - HANDSHAKE PHASE (Round {self.session.round})")
            
            # Prepare client info
            client_info = f"Client-{self.client_id}"
            plaintext = client_info.encode('utf-8')
            
            print(f"\n📤 SENDING CLIENT_HELLO")
            print(f"\033[92m[OPCODE 10: CLIENT_HELLO]\033[0m")
            print(f"  Plaintext: {client_info}")
            
            # Store keys before evolution for comparison
            old_c2s_enc = self.session.c2s_enc_key
            old_c2s_mac = self.session.c2s_mac_key
            
            # Construct CLIENT_HELLO message
            message = construct_message(
                Opcode.CLIENT_HELLO,
                self.client_id,
                self.session.round,
                Direction.CLIENT_TO_SERVER,
                plaintext,
                self.session.c2s_enc_key,
                self.session.c2s_mac_key
            )
            
            # Extract IV and ciphertext for display
            iv = message[7:23]
            ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
            hmac_tag = message[-HMAC_SIZE:]
            
            print_encryption_details(
                "CLIENT_HELLO Construction",
                Opcode="10 (CLIENT_HELLO)",
                ClientID=self.client_id,
                Round=self.session.round,
                Direction="1 (C2S)",
                IV=iv,
                Plaintext=plaintext,
                Ciphertext=ciphertext,
                HMAC=hmac_tag,
                MessageSize=f"{len(message)} bytes"
            )
            
            self.send_message(message)
            print(f"\n✓ CLIENT_HELLO sent successfully")
            
            # Receive SERVER_CHALLENGE
            print(f"\n📥 WAITING FOR SERVER_CHALLENGE...")
            print(f"\033[92m[EXPECTING OPCODE 20: SERVER_CHALLENGE]\033[0m")
            response = self.receive_message()
            return self.handle_server_challenge(response, plaintext, old_c2s_enc, old_c2s_mac)
            
        except ConnectionError as e:
            print(f"\n✗ [CLIENT {self.client_id}] Connection error in CLIENT_HELLO: {e}")
            print(f"\033[91m[SERVER CLOSED - CLIENT TERMINATING]\033[0m")
            self.session.terminate()
            return False
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Error in CLIENT_HELLO: {e}")
            import traceback
            traceback.print_exc()
            self.session.terminate()
            return False
    
    def handle_server_challenge(self, message: bytes, sent_plaintext: bytes, 
                                old_c2s_enc: bytes, old_c2s_mac: bytes) -> bool:
        """
        Handle SERVER_CHALLENGE response.
        
        Args:
            message: Received message
            sent_plaintext: Plaintext that was sent in CLIENT_HELLO (for key evolution)
            old_c2s_enc: C2S encryption key before evolution
            old_c2s_mac: C2S MAC key before evolution
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Extract components for display
            iv = message[7:23]
            ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
            hmac_tag = message[-HMAC_SIZE:]
            
            print_encryption_details(
                "SERVER_CHALLENGE Received",
                MessageSize=f"{len(message)} bytes",
                IV=iv,
                Ciphertext=ciphertext,
                HMAC=hmac_tag
            )
            
            print(f"\n🔓 DECRYPTING SERVER_CHALLENGE...")
            print(f"\033[92m[OPCODE 20: SERVER_CHALLENGE]\033[0m")
            print(f"  Using S2C Encryption Key: {self.session.s2c_enc_key.hex()}")
            print(f"  Using S2C MAC Key: {self.session.s2c_mac_key.hex()}")
            
            # Parse and decrypt message
            opcode, client_id, round_num, plaintext = parse_message(
                message,
                self.session.round,
                Direction.SERVER_TO_CLIENT,
                self.session.s2c_enc_key,
                self.session.s2c_mac_key
            )
            
            # Validate opcode
            if opcode != Opcode.SERVER_CHALLENGE:
                print(f"\n✗ Expected SERVER_CHALLENGE, got opcode {opcode}")
                self.session.terminate()
                return False
            
            # Parse challenge
            challenge_data = json.loads(plaintext.decode('utf-8'))
            print(f"\n✓ HMAC Verified and Decrypted Successfully!")
            print(f"  Decrypted Plaintext: {plaintext.decode('utf-8')}")
            print(f"  Challenge Message: {challenge_data['message']}")
            
            # Evolve keys
            nonce = bytes.fromhex(challenge_data['challenge'])
            
            print(f"\n🔄 KEY EVOLUTION PROCESS")
            print(f"{'─'*80}")
            
            # C2S keys evolution
            print(f"\n  C2S Key Evolution:")
            print(f"    Old C2S Enc Key: {old_c2s_enc.hex()}")
            print(f"    Old C2S MAC Key: {old_c2s_mac.hex()}")
            print(f"    Evolution Data (Enc): Sent plaintext = {sent_plaintext.hex()}")
            print(f"    Evolution Data (MAC): Server nonce = {nonce.hex()}")
            
            self.session.evolve_keys_c2s(sent_plaintext, nonce)
            
            print(f"    New C2S Enc Key: {self.session.c2s_enc_key.hex()}")
            print(f"    New C2S MAC Key: {self.session.c2s_mac_key.hex()}")
            
            # S2C keys evolution
            old_s2c_enc = self.session.s2c_enc_key
            old_s2c_mac = self.session.s2c_mac_key
            
            print(f"\n  S2C Key Evolution:")
            print(f"    Old S2C Enc Key: {old_s2c_enc.hex()}")
            print(f"    Old S2C MAC Key: {old_s2c_mac.hex()}")
            print(f"    Evolution Data (Enc): Challenge response = {plaintext.hex()[:64]}...")
            print(f"    Evolution Data (MAC): Status 'OK'")
            
            self.session.evolve_keys_s2c(plaintext, b'OK')
            
            print(f"    New S2C Enc Key: {self.session.s2c_enc_key.hex()}")
            print(f"    New S2C MAC Key: {self.session.s2c_mac_key.hex()}")
            
            # Transition to ACTIVE phase and advance round
            self.session.activate()
            self.session.advance_round()
            
            print(f"\n✓ HANDSHAKE COMPLETE!")
            print(f"  Protocol Phase: {self.session.phase.name}")
            print(f"  Current Round: {self.session.round}")
            
            print_key_info(self.session, "Keys After Handshake")
            
            return True
            
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Error handling SERVER_CHALLENGE: {e}")
            import traceback
            traceback.print_exc()
            self.session.terminate()
            return False
    
    def send_data(self, data_value: float) -> bool:
        """
        Send CLIENT_DATA with numeric value.
        
        Args:
            data_value: Numeric data to send
        
        Returns:
            True if successful, False otherwise
        """
        if self.session.phase != ProtocolPhase.ACTIVE:
            print(f"\n✗ [CLIENT {self.client_id}] Cannot send data: not in ACTIVE phase")
            return False
        
        try:
            print_header(f"CLIENT {self.client_id} - DATA EXCHANGE (Round {self.session.round})")
            
            # Prepare data payload
            data_payload = {
                'data': data_value,
                'timestamp': time.time(),
                'client_id': self.client_id
            }
            plaintext = json.dumps(data_payload).encode('utf-8')
            
            print(f"\n📤 SENDING CLIENT_DATA")
            print(f"\033[92m[OPCODE 30: CLIENT_DATA]\033[0m")
            print(f"  Data Value: {data_value}")
            print(f"  Full Payload: {data_payload}")
            
            # Store keys before evolution
            old_c2s_enc = self.session.c2s_enc_key
            old_c2s_mac = self.session.c2s_mac_key
            old_s2c_enc = self.session.s2c_enc_key
            old_s2c_mac = self.session.s2c_mac_key
            
            # Construct CLIENT_DATA message
            message = construct_message(
                Opcode.CLIENT_DATA,
                self.client_id,
                self.session.round,
                Direction.CLIENT_TO_SERVER,
                plaintext,
                self.session.c2s_enc_key,
                self.session.c2s_mac_key
            )
            
            # Extract components
            iv = message[7:23]
            ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
            hmac_tag = message[-HMAC_SIZE:]
            
            print_encryption_details(
                "CLIENT_DATA Construction",
                Opcode="30 (CLIENT_DATA)",
                ClientID=self.client_id,
                Round=self.session.round,
                Direction="1 (C2S)",
                IV=iv,
                Plaintext=plaintext,
                Ciphertext=ciphertext,
                HMAC=hmac_tag,
                MessageSize=f"{len(message)} bytes"
            )
            
            self.send_message(message)
            print(f"\n✓ CLIENT_DATA sent successfully")
            
            # Receive SERVER_AGGR_RESPONSE
            print(f"\n📥 WAITING FOR SERVER_AGGR_RESPONSE...")
            print(f"\033[92m[EXPECTING OPCODE 40: SERVER_AGGR_RESPONSE]\033[0m")
            response = self.receive_message()
            return self.handle_server_response(response, message, old_c2s_enc, old_c2s_mac, 
                                               old_s2c_enc, old_s2c_mac)
            
        except ConnectionError as e:
            print(f"\n✗ [CLIENT {self.client_id}] Connection error sending data: {e}")
            print(f"\033[91m[SERVER CLOSED - CLIENT TERMINATING]\033[0m")
            self.session.terminate()
            return False
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Error sending data: {e}")
            import traceback
            traceback.print_exc()
            self.session.terminate()
            return False
    
    def handle_server_response(self, message: bytes, sent_message: bytes,
                               old_c2s_enc: bytes, old_c2s_mac: bytes,
                               old_s2c_enc: bytes, old_s2c_mac: bytes) -> bool:
        """
        Handle SERVER_AGGR_RESPONSE.
        
        Args:
            message: Received message
            sent_message: Original CLIENT_DATA message (for key evolution)
            old_c2s_enc: C2S encryption key before evolution
            old_c2s_mac: C2S MAC key before evolution
            old_s2c_enc: S2C encryption key before evolution
            old_s2c_mac: S2C MAC key before evolution
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Extract components
            iv = message[7:23]
            ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
            hmac_tag = message[-HMAC_SIZE:]
            
            print_encryption_details(
                "SERVER_AGGR_RESPONSE Received",
                MessageSize=f"{len(message)} bytes",
                IV=iv,
                Ciphertext=ciphertext,
                HMAC=hmac_tag
            )
            
            print(f"\n🔓 DECRYPTING SERVER_AGGR_RESPONSE...")
            print(f"\033[92m[OPCODE 40: SERVER_AGGR_RESPONSE]\033[0m")
            print(f"  Using S2C Encryption Key: {self.session.s2c_enc_key.hex()}")
            print(f"  Using S2C MAC Key: {self.session.s2c_mac_key.hex()}")
            
            # Parse and decrypt message
            opcode, client_id, round_num, plaintext = parse_message(
                message,
                self.session.round,
                Direction.SERVER_TO_CLIENT,
                self.session.s2c_enc_key,
                self.session.s2c_mac_key
            )
            
            # Check opcode
            if opcode == Opcode.SERVER_AGGR_RESPONSE:
                # Parse aggregate response
                response_data = json.loads(plaintext.decode('utf-8'))
                
                print(f"\n✓ HMAC Verified and Decrypted Successfully!")
                print(f"  Decrypted Plaintext: {plaintext.decode('utf-8')}")
                
                print(f"\n📊 AGGREGATE RESPONSE:")
                print(f"  Total Sum           : {response_data['aggregate_sum']}")
                print(f"  Data Count          : {response_data['data_count']}")
                print(f"  Your Contribution   : {response_data['your_contribution']}")
                print(f"  Round               : {response_data['round']}")
                
                # Extract nonce from response (server-generated)
                nonce = bytes.fromhex(response_data['nonce'])
                
                # Evolve keys
                print(f"\n🔄 KEY EVOLUTION PROCESS")
                print(f"{'─'*80}")
                
                # C2S keys
                sent_ciphertext = sent_message[HEADER_SIZE:-HMAC_SIZE]
                
                print(f"\n  C2S Key Evolution:")
                print(f"    Old C2S Enc Key: {old_c2s_enc.hex()}")
                print(f"    Old C2S MAC Key: {old_c2s_mac.hex()}")
                print(f"    Evolution Data (Enc): Sent ciphertext = {sent_ciphertext.hex()[:64]}...")
                print(f"    Evolution Data (MAC): Server nonce = {nonce.hex()}")
                
                self.session.evolve_keys_c2s(sent_ciphertext, nonce)
                
                print(f"    New C2S Enc Key: {self.session.c2s_enc_key.hex()}")
                print(f"    New C2S MAC Key: {self.session.c2s_mac_key.hex()}")
                
                # S2C keys
                print(f"\n  S2C Key Evolution:")
                print(f"    Old S2C Enc Key: {old_s2c_enc.hex()}")
                print(f"    Old S2C MAC Key: {old_s2c_mac.hex()}")
                print(f"    Evolution Data (Enc): Response data = {plaintext.hex()[:64]}...")
                print(f"    Evolution Data (MAC): Status 'OK'")
                
                self.session.evolve_keys_s2c(plaintext, b'OK')
                
                print(f"    New S2C Enc Key: {self.session.s2c_enc_key.hex()}")
                print(f"    New S2C MAC Key: {self.session.s2c_mac_key.hex()}")
                
                # Advance round
                self.session.advance_round()
                
                print(f"\n✓ DATA EXCHANGE COMPLETE!")
                print(f"  Current Round: {self.session.round}")
                
                print_key_info(self.session, f"Keys After Round {response_data['round']}")
                
                return True
                
            elif opcode == Opcode.KEY_DESYNC_ERROR:
                error_msg = plaintext.decode('utf-8')
                print(f"\n✗ [CLIENT {self.client_id}] Server reported error: {error_msg}")
                self.session.terminate()
                return False
                
            elif opcode == Opcode.TERMINATE:
                reason = plaintext.decode('utf-8')
                print(f"\n\033[91m✗ [CLIENT {self.client_id}] Server terminated session: {reason}\033[0m")
                print(f"\033[91m[SERVER SHUTDOWN - CLIENT TERMINATING]\033[0m")
                self.session.terminate()
                return False
                
            else:
                print(f"\n✗ [CLIENT {self.client_id}] Unexpected opcode: {opcode}")
                self.session.terminate()
                return False
                
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Error handling server response: {e}")
            import traceback
            traceback.print_exc()
            self.session.terminate()
            return False
    
    def run_interactive_session(self):
        """
        Run interactive client session with real-time communication.
        """
        print_separator('=')
        print(f"  SECURE CLIENT {self.client_id} - INTERACTIVE MODE")
        print_separator('=')
        
        # Connect to server
        if not self.connect():
            return
        
        try:
            # Perform handshake
            if not self.send_client_hello():
                print(f"\n✗ [CLIENT {self.client_id}] Handshake failed")
                return
            
            print(f"\n{'='*80}")
            print(f"  🎉 CLIENT {self.client_id} READY FOR DATA EXCHANGE")
            print(f"{'='*80}")
            print(f"\nYou can now send numeric data to the server.")
            print(f"The server will aggregate data from all connected clients.")
            print(f"\nCommands:")
            print(f"  - Enter a number to send data")
            print(f"  - Type 'quit' or 'exit' to disconnect")
            print(f"  - Type 'keys' to view current keys")
            print(f"  - Type 'status' to view session status")
            print(f"{'='*80}\n")
            
            # Interactive loop
            while not self.session.is_terminated():
                try:
                    user_input = input(f"[Client {self.client_id} | Round {self.session.round}] Enter data: ").strip()
                    
                    if not user_input:
                        continue
                    
                    if user_input.lower() in ['quit', 'exit']:
                        print(f"\n[CLIENT {self.client_id}] Disconnecting...")
                        break
                    
                    if user_input.lower() == 'keys':
                        print_key_info(self.session, f"Current Keys (Round {self.session.round})")
                        continue
                    
                    if user_input.lower() == 'status':
                        print(f"\n{'─'*80}")
                        print(f"SESSION STATUS")
                        print(f"{'─'*80}")
                        print(f"  Client ID       : {self.client_id}")
                        print(f"  Current Round   : {self.session.round}")
                        print(f"  Protocol Phase  : {self.session.phase.name}")
                        print(f"  Session State   : {'ACTIVE' if not self.session.is_terminated() else 'TERMINATED'}")
                        print(f"{'─'*80}\n")
                        continue
                    
                    # Try to parse as float
                    try:
                        data_value = float(user_input)
                    except ValueError:
                        print(f"✗ Invalid input. Please enter a numeric value.")
                        continue
                    
                    # Send data
                    if not self.send_data(data_value):
                        print(f"\n✗ [CLIENT {self.client_id}] Data exchange failed")
                        break
                    
                    print(f"\n{'='*80}\n")
                    
                except ConnectionError as e:
                    print(f"\n\n\033[91m✗ [CLIENT {self.client_id}] Connection lost: {e}\033[0m")
                    print(f"\033[91m[SERVER CLOSED - CLIENT TERMINATING]\033[0m")
                    break
                except KeyboardInterrupt:
                    print(f"\n\n[CLIENT {self.client_id}] Interrupted by user")
                    break
                except EOFError:
                    print(f"\n\n[CLIENT {self.client_id}] EOF received")
                    break
                except Exception as e:
                    print(f"\n\n\033[91m✗ [CLIENT {self.client_id}] Error: {e}\033[0m")
                    break
            
            print(f"\n[CLIENT {self.client_id}] Session ended")
            
        except Exception as e:
            print(f"\n✗ [CLIENT {self.client_id}] Session error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.disconnect()
            
        print_separator('=')
        print(f"  CLIENT {self.client_id} SESSION ENDED")
        print_separator('=')


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main client entry point"""
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id>")
        print("Example: python client.py 1")
        print("\nAvailable client IDs: 1, 2, 3, 4, 5")
        sys.exit(1)
    
    client_id = int(sys.argv[1])
    
    # Pre-shared master keys (must match server)
    MASTER_KEYS = {
        1: bytes.fromhex('0123456789abcdef0123456789abcdef'),
        2: bytes.fromhex('fedcba9876543210fedcba9876543210'),
        3: bytes.fromhex('11112222333344445555666677778888'),
        4: bytes.fromhex('aaaabbbbccccddddeeeeffffaaaabbbb'),
        5: bytes.fromhex('00001111222233334444555566667777'),
    }
    
    if client_id not in MASTER_KEYS:
        print(f"Error: Unknown client ID {client_id}")
        print(f"Valid client IDs: {list(MASTER_KEYS.keys())}")
        sys.exit(1)
    
    master_key = MASTER_KEYS[client_id]
    
    # Create and run client in interactive mode
    client = SecureClient(client_id, master_key, SERVER_HOST, SERVER_PORT)
    client.run_interactive_session()


if __name__ == "__main__":
    main()
