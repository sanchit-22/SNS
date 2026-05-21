# SECURITY.md — Security Analysis

## How the Protocol Ensures Freshness

### Timestamps (TS)

Every protocol message includes a timestamp:

- **Phase 0**: `TS0` — when MCC generated the parameters.
- **Phase 1A**: `TS_i` — when the drone sent the authentication request.
- **Phase 1B**: `TS_MCC` — when MCC responded.
- **Phase 2**: `TS_final` — included in the HMAC confirmation.

Both sides enforce a **±30 second freshness window**. If a message's timestamp falls outside this window, the recipient rejects it. This prevents **replay attacks** because a captured message becomes stale within seconds.

### Nonces (RN)

- **Phase 1A**: The drone generates a cryptographically random 2048-bit nonce `RN_i`.
- **Phase 1B**: MCC generates its own random nonce `RN_MCC`.

Both nonces feed into the session-key derivation:

$$SK = \text{SHA-256}(K \| TS_i \| TS_{MCC} \| RN_i \| RN_{MCC})$$

Even if two handshakes use the same secret $K$, different nonces guarantee a different session key. An attacker replaying an old `AUTH_REQ` will produce a mismatched session key because the nonces and timestamps differ, causing the HMAC verification in Phase 2 to fail.

### Signed Parameters (Phase 0)

The MCC signs the concatenation $\langle p \| g \| SL \| TS_0 \| ID_{MCC} \rangle$ with its ElGamal private key. This serves two freshness purposes:

1. The timestamp `TS0` binds the parameters to the current session.
2. The signature prevents an attacker from replaying old (potentially weakened) parameters.

---

## How the Protocol Ensures Forward Secrecy

### Ephemeral Session Keys

The shared secret $K_{D_i, MCC}$ is generated **freshly for every handshake** by the drone as a random value in $[1, p-2]$. The resulting session key:

$$SK_{D_i, MCC} = H(K_{D_i,MCC} \| TS_i \| TS_{MCC} \| RN_i \| RN_{MCC})$$

is therefore **ephemeral**. Compromise of a future private key does not reveal past session keys because:

- Each $K$ is randomly chosen and encrypted under the recipient's public key.
- Even if the MCC's long-term private key $x_{MCC}$ is later compromised, the attacker would need the specific ciphertext **and** the ability to decrypt it, but the random $k$ used in ElGamal encryption is also ephemeral and not stored.

### Group Key Derivation

The group key:

$$GK = H(SK_{D_1} \| SK_{D_2} \| \cdots \| SK_{D_n} \| KR_{MCC})$$

is derived from **all active session keys** plus the MCC's private key material. Because session keys change every handshake (and the group key is re-derived before every broadcast per TA clarification), past group keys cannot be recovered from future compromises.

### Key Material Not Stored Long-Term

- The random $k$ used in each ElGamal encryption is generated, used once, and discarded.
- Session keys are held only in memory during the active session.
- The shared secret $K$ is not persisted after session-key derivation.

This combination of **ephemeral secrets**, **nonce mixing**, and **timestamp binding** provides **forward secrecy**: compromise of long-term keys does not retroactively expose past session traffic.

---

## Additional Security Properties

| Property                  | Mechanism                                                                                                |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Mutual Authentication** | Both sides sign their messages with ElGamal; each verifies the other's signature.                        |
| **Integrity**             | HMAC-SHA256 on broadcast commands; ElGamal signatures on handshake messages.                             |
| **Confidentiality**       | Shared secret encrypted with ElGamal; broadcast commands encrypted with AES-256-CBC using the group key. |
| **Downgrade Prevention**  | Drone checks `SL ≥ 2048` and verifies `bit_length(p) ≈ SL`; MCC signs parameters.                        |
| **Replay Prevention**     | Timestamps with freshness window + random nonces in session key derivation.                              |
