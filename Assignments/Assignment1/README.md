# Secure Multi-Client Communication with Symmetric Keys

**CS5.470 - System and Network Security**  
**Lab Assignment 1**

## Overview

This project implements a stateful, symmetric-key-based secure communication protocol between a server and multiple clients operating in a hostile network environment. The protocol ensures confidentiality, integrity, freshness, and synchronization using only symmetric cryptographic techniques.

## Features

- ✅ **Stateful Protocol**: Maintains round numbers, key evolution, and protocol phases
- ✅ **Multi-Client Support**: Server handles multiple simultaneous clients
- ✅ **Key Evolution (Ratcheting)**: Keys evolve after each message exchange
- ✅ **Attack Resistance**: Defends against replay, tampering, desynchronization, and reflection attacks
- ✅ **Manual Cryptography**: PKCS#7 padding, AES-128-CBC, HMAC-SHA256 implemented manually
- ✅ **Comprehensive Testing**: Attack simulation suite demonstrates security properties

## Project Structure

```
Assignment1/
├── crypto_utils.py       # Cryptographic primitives (AES-CBC, PKCS#7, HMAC)
├── protocol_fsm.py       # Protocol finite state machine
├── server.py            # Multi-client server implementation
├── client.py            # Client implementation
├── attacks.py           # Attack demonstration suite
├── README.md            # This file
└── SECURITY.md          # Security analysis and defense mechanisms
```

## Requirements

- Python 3.8 or higher
- `pycryptodome` library (for raw AES block cipher only)

## Installation

1. **Create and activate virtual environment:**

   ```bash
   python3 -m venv myenv
   source myenv/bin/activate  # On Linux/Mac
   # or
   myenv\Scripts\activate     # On Windows
   ```

2. **Install dependencies:**
   ```bash
   pip install pycryptodome
   ```

## Usage

### Running the Server

Start the server in one terminal:

```bash
python server.py
```

The server will listen on `127.0.0.1:9999` and wait for client connections.

### Running Clients (Interactive Mode)

In separate terminals, start one or more clients:

```bash
# Client 1
python client.py 1

# Client 2 (in another terminal)
python client.py 2
```

**Interactive Commands**:

- Enter a number to send data (e.g., `42`, `3.14`, `-5`)
- Type `keys` to view current encryption/MAC keys
- Type `status` to view session status (round, phase)
- Type `quit` or `exit` to disconnect

**Features**:

- ✅ Real-time data entry (no hardcoded message count)
- ✅ Detailed encryption/decryption information after each message
- ✅ Key evolution tracking and display
- ✅ Verify that encryption is working correctly at each step
- ✅ Shows IV, ciphertext, and HMAC for every message
- ✅ Displays key changes after each round

# Client 3 (in another terminal)

python client.py 3 5

````

**Arguments:**

- First argument: Client ID (1-5)
- Second argument: Number of data messages to send (default: 5)

### Running Attack Demonstrations

To see how the protocol defends against various attacks:

```bash
python attacks.py
````

This will demonstrate:

1. Replay Attack
2. Message Reordering Attack
3. HMAC Tampering Attack
4. Key Desynchronization Attack
5. Round Number Manipulation Attack
6. Reflection Attack
7. Truncation Attack

## Protocol Overview

### Message Format

```
| Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
| Ciphertext (variable) | HMAC (32) |
```

### Opcodes

| Opcode | Name                 | Description                |
| ------ | -------------------- | -------------------------- |
| 10     | CLIENT_HELLO         | Client initiates protocol  |
| 20     | SERVER_CHALLENGE     | Encrypted server challenge |
| 30     | CLIENT_DATA          | Encrypted client data      |
| 40     | SERVER_AGGR_RESPONSE | Encrypted aggregate result |
| 50     | KEY_DESYNC_ERROR     | Desynchronization detected |
| 60     | TERMINATE            | Session termination        |

### Protocol Phases

1. **INIT**: Initial handshake phase

   - Client sends `CLIENT_HELLO`
   - Server responds with `SERVER_CHALLENGE`
   - Keys evolve, transition to ACTIVE

2. **ACTIVE**: Data exchange phase

   - Client sends `CLIENT_DATA` with numeric values
   - Server aggregates data from all clients
   - Server responds with `SERVER_AGGR_RESPONSE`
   - Keys evolve after each exchange
   - Round number increments

3. **TERMINATED**: Session ended
   - Triggered by protocol violations or errors
   - No further communication allowed

### Key Initialization

Each client shares a unique master key `K_i` with the server.

**Initial key derivation:**

```
C2S_Enc_0 = H(K_i || "C2S-ENC")
C2S_Mac_0 = H(K_i || "C2S-MAC")
S2C_Enc_0 = H(K_i || "S2C-ENC")
S2C_Mac_0 = H(K_i || "S2C-MAC")
```

### Key Evolution

Keys evolve after each successful message exchange:

**Client-to-Server:**

```
C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
```

**Server-to-Client:**

```
S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
```

### Encryption/Decryption Procedure

**Encryption (Sender):**

1. Apply PKCS#7 padding to plaintext
2. Generate fresh random IV (16 bytes)
3. Encrypt using AES-128-CBC
4. Construct message header
5. Compute HMAC over (Header || Ciphertext)
6. Transmit (Header || Ciphertext || HMAC)

**Decryption (Receiver):**

1. Verify round number and direction
2. **Verify HMAC BEFORE decryption** (critical!)
3. If HMAC fails, terminate session immediately
4. Decrypt ciphertext using AES-128-CBC
5. Remove PKCS#7 padding
6. Validate plaintext format

## Security Properties

### Confidentiality

- All payloads encrypted with AES-128-CBC
- Fresh random IV for each message
- Keys evolve to provide forward secrecy

### Integrity

- HMAC-SHA256 protects against tampering
- Verification done **before** decryption
- Padding oracle attacks prevented

### Freshness

- Round numbers prevent replay attacks
- Keys evolve, making old messages invalid
- Timestamps in data payloads

### Synchronization

- Strict round number validation
- Phase-based state machine
- Key desynchronization detection

### Attack Resistance

- **Replay**: Rejected due to round mismatch
- **Reordering**: Enforced sequential processing
- **Tampering**: Detected by HMAC verification
- **Reflection**: Direction field prevents reflection
- **Desynchronization**: HMAC fails, session terminates

## Configuration

### Master Keys

Pre-shared master keys are defined in `server.py` and `client.py`:

```python
CLIENT_MASTER_KEYS = {
    1: bytes.fromhex('0123456789abcdef0123456789abcdef'),
    2: bytes.fromhex('fedcba9876543210fedcba9876543210'),
    3: bytes.fromhex('11112222333344445555666677778888'),
    4: bytes.fromhex('aaaabbbbccccddddeeeeffffaaaabbbb'),
    5: bytes.fromhex('00001111222233334444555566667777'),
}
```

**Note:** In production, these should be loaded from secure key management systems.

### Network Settings

Default settings in all files:

```python
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
```

Modify these if running on different network configurations.

## Testing

### Unit Tests

Each module includes unit tests. Run them individually:

```bash
# Test cryptographic primitives
python crypto_utils.py

# Test protocol FSM
python protocol_fsm.py
```

### Integration Testing

1. Start the server
2. Run multiple clients simultaneously
3. Observe message exchanges and aggregation
4. Verify round progression and key evolution

### Security Testing

Run the attack suite:

```bash
python attacks.py
```

Expected output: All attacks should be successfully defended against.

## Code Quality

### Design Principles

- **Modularity**: Clear separation of concerns
- **Documentation**: Comprehensive docstrings and comments
- **Error Handling**: Robust exception handling throughout
- **Type Hints**: Used where applicable for clarity
- **Security First**: Defensive programming practices

### Key Design Decisions

1. **HMAC Before Decryption**: Prevents padding oracle and other timing attacks
2. **Strict State Validation**: Every message checked against current protocol state
3. **Session Termination**: Any violation immediately terminates session
4. **Key Evolution**: Provides forward secrecy and replay resistance
5. **No Automatic Padding**: Manual PKCS#7 to demonstrate understanding

## Troubleshooting

### Connection Refused

- Ensure server is running before starting clients
- Check firewall settings
- Verify `SERVER_HOST` and `SERVER_PORT` match

### HMAC Verification Failed

- Check that master keys match between client and server
- Ensure no concurrent modifications to same client ID
- Verify network is not corrupting packets

### Key Desynchronization

- If client and server get out of sync, restart both
- This is expected behavior for the protocol (fail-secure)

### Import Errors

- Ensure virtual environment is activated
- Install `pycryptodome`: `pip install pycryptodome`

## Limitations

1. **No Public Key Cryptography**: Uses only symmetric keys
2. **Pre-Shared Keys**: Requires out-of-band key distribution
3. **TCP Only**: Uses TCP, no UDP support
4. **No Key Refresh**: Session keys not periodically refreshed (could be added)
5. **Limited Clients**: Pre-configured for 5 clients (easily extensible)

## Future Enhancements

- [ ] Add TLS for transport layer security
- [ ] Implement key refresh mechanism
- [ ] Add support for dynamic client registration
- [ ] Include message sequence numbers in addition to rounds
- [ ] Add logging to file for audit trail
- [ ] Implement graceful session closure protocol
- [ ] Add client authentication beyond just key possession

## References

- AES: FIPS 197
- HMAC: RFC 2104
- PKCS#7 Padding: RFC 2315
- CBC Mode: NIST SP 800-38A

## Authors

CS5.470 Lab Assignment 1  
International Institute of Information Technology, Hyderabad

## License

Academic use only - CS5.470 Lab Assignment

---

For detailed security analysis, see [SECURITY.md](SECURITY.md).
