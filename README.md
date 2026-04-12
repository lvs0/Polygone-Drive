# ⬡ Polygone-Drive

**Distributed, Post-Quantum, Pinned Storage.**

> ⚠️ **Architecture Clarification**: Polygone-Drive uses the same cryptographic primitives as the ephemeral Polygone network (ML-KEM, Shamir Secret Sharing, AES-256-GCM), but with a different persistence model. Files are pinned on dedicated storage nodes, not subject to the 30s TTL of the message network.

---

## The Problem: Storage vs Ephemeral

The Polygone message network is **ephemeral** — messages vaporize after 30 seconds. This is perfect for metadata-hidden communication, but **not** for file storage.

Polygone-Drive solves this by:

1. **Same crypto**: ML-KEM-1024 key exchange + Shamir 4-of-7 fragmentation
2. **Different transport**: Dedicated storage nodes with pinning (not DHT TTL)
3. **Same privacy**: No single node knows what it's storing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Polygone-Drive                          │
├─────────────────────────────────────────────────────────────┤
│  File → Chunker → Sharding → Encryption → Pinned Storage  │
│                                                             │
│  [Alice] uploads file                                       │
│       ↓                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 1. Split into chunks (1MB each)                       │  │
│  │ 2. Encrypt each chunk (AES-256-GCM)                  │  │
│  │ 3. Shamir-split each encrypted chunk (4-of-7)         │  │
│  │ 4. Distribute fragments to pinned storage nodes        │  │
│  └──────────────────────────────────────────────────────┘  │
│       ↓                                                    │
│  [Bob] downloads with token                                │
│       ↓                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 1. Collect ≥4 fragments from storage nodes            │  │
│  │ 2. Reconstruct Shamir shares                         │  │
│  │ 3. Decrypt with recipient's key                      │  │
│  │ 4. Reassemble file                                   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Usage

```bash
# Upload a file
polygone-drive upload myfile.pdf --recipient peer.pubkey

# Share with a link
polygone-drive share myfile.pdf.pgd
# Output: poly://<base64_token>

# Download
polygone-drive download --token poly://<token> --sk my.key

# Run a storage node
polygone-drive node --cache-gb 100
```

---

## Key Features

- **Vapor Streaming**: Stream large files before download completes
- **Post-Quantum**: ML-KEM-1024 + ML-DSA-87
- **Secret Sharing**: No node knows the full file
- **Anonymous Pins**: Storage nodes don't know what they're storing

---

## Building

```bash
cargo build --release
./target/release/polygone-drive help
```

---

**License**: MIT  
**Author**: l-vs (Hope)
