# Phantom

Tiny end-to-end encrypted messaging for the command line.

Project page: **https://noks.pics/phantom**

<img width="896" height="496" alt="phantom-menu" src="https://github.com/user-attachments/assets/2806b8ab-d2ee-4fe9-924d-ea559a6a1990" />

Phantom encrypts messages on your device before they leave.
The relay stores ciphertext and routing data, but does not decrypt message content.

No accounts. No emails. No phone numbers.

Network anonymity is your responsibility: use Tor (recommended) or a trusted VPN.

---

## Overview

Phantom is a Python CLI messenger with:

- Client-side E2EE (X25519 + HKDF + ChaCha20-Poly1305)
- UID derived from your public key
- No account registration tied to personal identity
- Ed25519 request signing for authenticated relay endpoints
- Tor support with privacy preflight warnings
- File attachments encrypted client-side
- Burn requests to delete room ciphertext from relay storage
- Automatic relay-side retention cleanup

This is not a web messenger. It is a local client that talks to a relay.

---

## Security Model

### What Phantom Protects

- Message/file content from relay compromise
- Message/file content from DB or object-storage leaks
- Identity linkage to phone/email (none used)
- Server-side decryption (not possible without client keys)

### What Phantom Does Not Automatically Protect

- Your IP address (unless traffic is routed via Tor/VPN)
- Identity you reveal inside messages
- A compromised endpoint/device
- Powerful traffic-correlation adversaries

Encryption protects content.
Tor protects network identity.

---

## How It Works

1. **Identity is local**
   The client generates X25519 (encryption) and Ed25519 (signing) keypairs and encrypts them at rest with your password.

2. **UID is derived from pubkey**
   Your address is generated from your public key.

3. **Room and session derivation**
   Peers derive deterministic room IDs and session keys from ECDH + HKDF.

4. **Message encryption**
   Messages are encrypted on-device before upload.

5. **Sender attribution in ciphertext**
   Sender identity is carried in an encrypted message envelope (`PHANTOM_MSG_V1`) rather than plaintext relay payloads.

6. **Relay routes/stores ciphertext**
   Relay enforces auth, room membership, retention, and burn operations.

---

## Metadata (Current)

What the relay still needs for operation:

- User registration records (`uid`, public keys, rounded registration timestamp)
- Room membership mapping (`room_id` + participant UIDs)
- Message rows keyed by room and time (`room_id`, `ciphertext`, `ts`)
- Key-exchange inbox entries (`from_uid`, `to_uid`, `pub_key`, `ts`)
- File blobs in object storage with opaque keys

Metadata reductions in current client/relay flow:

- File URLs are opaque encrypted IDs (not reversible to filename/room)
- File upload transport metadata uses generic multipart filename/type
- Message fetch/broadcast payloads do not require plaintext `sender_id`

What is still visible without Tor/VPN:

- Source IP at network/infrastructure layers
- Request timing/volume patterns
- Room identifiers in certain endpoints (for example WebSocket path)

---

## Installation

### Quick start (Linux / macOS)

```bash
curl -fsSL https://noks.pics/phantom.py -o phantom.py
python3 phantom.py
```

### Windows (PowerShell)

```powershell
Invoke-WebRequest https://noks.pics/phantom.py -OutFile phantom.py
py -3 phantom.py
```

Dependencies are auto-installed on first run.

Manual install:

```bash
python -m pip install -r requirements.txt
```

---

## First Run

On first launch, Phantom:

- checks relay connectivity
- creates local identity keys
- prompts for password protection
- displays your UID

Back up:

```text
~/.phantom/identity.json
```

If you lose password + identity file, identity is unrecoverable.

---

## Tor Usage (Recommended)

Linux example:

```bash
sudo apt install tor
sudo systemctl enable --now tor
```

Phantom auto-detects Tor at `127.0.0.1:9050`.

If Tor is not running, Phantom warns before network actions.

---

## In-Chat Commands

```text
/file <path>
/files
/get <n> [path]
/burn
/quit
```

### File Attachments

- Max size default: 50 MB (relay configurable)
- Files encrypted client-side before upload
- Relay stores encrypted blobs only
- Default file retention: 24 hours

---

## Burn

`/burn` requests relay-side deletion of ciphertext in the current room.

- Does not delete local copies
- Rate-limited
- Authenticated with per-user relay auth key flow
- Does not guarantee remote peer deletion

---

## Retention Defaults (Relay)

- Messages: 7 days
- Key-exchange entries: 24 hours
- Files: 24 hours

Retention is enforced by scheduled purge on the relay.

---

## Update Mechanism

Phantom supports:

- version checks
- optional self-update
- TLS SPKI pinning for update endpoint trust

If update key pin mismatches, auto-update is blocked until user approval.

---

## Configuration Notes (Relay)

Key environment variables include:

- `MESSAGE_RETENTION_DAYS`
- `KE_RETENTION_HOURS`
- `FILE_RETENTION_HOURS`
- `MAX_FILE_SIZE_BYTES`
- `PHANTOM_AUTH_PRIV_B64`
- `PHANTOM_FILE_ID_KEY_B64` (set this to a stable 32-byte base64 key so file IDs survive restarts)

---

## Limitations

Phantom is a minimal encrypted messenger. It is not:

- a full anonymity network
- a Tor replacement
- a hardened OS
- resistant to endpoint compromise
- a multi-device identity sync platform

For stronger anonymity and safety:

- use Tor
- verify contact keys out-of-band
- avoid sharing identifying details
- use secure devices

---

## Philosophy

Small. Practical. Auditable.

No accounts.
Minimal metadata.
Short retention.
Client-side encryption.

Privacy by architecture, not marketing.
