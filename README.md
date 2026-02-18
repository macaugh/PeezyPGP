# PeezyPGP

[![Swift](https://img.shields.io/badge/Swift-5.9-F05138.svg?logo=swift&logoColor=white)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2015%2B%20%7C%20macOS%2012%2B-lightgrey.svg?logo=apple)](https://developer.apple.com)
[![RFC 9580](https://img.shields.io/badge/spec-RFC%209580-0057b7.svg)](https://www.rfc-editor.org/rfc/rfc9580)
[![License](https://img.shields.io/badge/license-MIT-22c55e.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-purple.svg)]()

**Privacy-first OpenPGP for iOS and macOS — built entirely on Apple CryptoKit with zero third-party libraries.**

PeezyPGP implements the modern OpenPGP standard (RFC 9580) using Ed25519 signing, X25519 key agreement, and AES-256-GCM encryption. Private keys are wrapped by the Secure Enclave, stored in the Apple Keychain, and unlocked with Face ID or Touch ID. The app has no network entitlements — it cannot phone home, sync keys, or collect data.

---

## Why This Exists

Most PGP tools on Apple platforms fall into one of three traps:

1. **Ancient C libraries** — libgcrypt or BouncyCastle compiled for mobile, carrying years of implementation debt
2. **Outdated algorithms** — RSA-2048 keys with SHA-1 fingerprints and iterated S2K
3. **Broken trust model** — analytics, cloud sync, or keys stored in plaintext SQLite

PeezyPGP takes the opposite path. Modern curves. Apple's own audited crypto primitives. No network entitlements — not by policy, but by capability, enforced at the OS level. Zero supply chain risk because there's no supply chain.

---

## Cryptographic Stack

| Layer | Algorithm | Standard | Implementation |
|-------|-----------|----------|----------------|
| Signing | Ed25519 | RFC 8032 | CryptoKit |
| Key Agreement | X25519 | RFC 7748 | CryptoKit |
| Symmetric Encryption | AES-256-GCM | NIST FIPS 197 | CryptoKit |
| Passphrase KDF | Argon2id | RFC 9106 | CryptoKit / HKDF |
| ECDH KDF | HKDF-SHA-256 | RFC 5869 | CryptoKit |
| Hashing | SHA-256 / SHA-512 | FIPS 180-4 | CryptoKit |
| Key Storage | Secure Enclave P-256 | — | Security.framework |

Every algorithm is either directly from CryptoKit or a composition of CryptoKit primitives. No custom elliptic curve arithmetic. No rolling your own AES.

---

## Key Hierarchy

```
User Passphrase  (memorized, never stored)
    │
    └── Key Encryption Key (KEK)
            derived via Argon2id — 64 MiB / 4 iterations on mobile
            never persisted
        │
        └── OpenPGP Private Keys  (stored in Keychain)
                Ed25519 signing key  — encrypted with KEK + AES-256-GCM
                X25519 encrypt key   — encrypted with KEK + AES-256-GCM
            │
            └── Secure Enclave KEK  (optional, hardware-bound)
                    P-256 key that never leaves the Secure Enclave
                    wraps the encrypted private key blobs
                    gated by biometric authentication
                │
                └── Session Keys  (ephemeral, per-message)
                        generated fresh for every encryption operation
                        never written to disk
```

---

## Features

**Keys**
- Generate Ed25519 (signing) + X25519 (encryption) key pairs
- Import public keys from ASCII armor
- Export public and private keys to ASCII armor
- Hardware-backed storage via Secure Enclave
- Face ID / Touch ID on every private key use

**Crypto Operations**
- Encrypt messages to any imported public key (PKESK + SEIPD v2 packets)
- Decrypt with biometric-gated private key
- Sign messages with Ed25519 detached signatures
- Verify signatures against public keys
- Full ASCII armor encode/decode with CRC-24

**Platform**
- Native SwiftUI on both iOS and macOS (no Mac Catalyst hacks)
- iOS 15+ tab-based navigation
- macOS 12+ split-view with sidebar
- Dark mode, Dynamic Type, VoiceOver

**Security**
- `SecureBytes` — custom buffer type that calls `memset_s` on deallocation
- `defer` blocks ensure zeroing even when functions throw
- Zero network entitlements (enforced by App Sandbox, not just code)
- No analytics, no telemetry, no third-party SDKs

---

## Building Locally

### Requirements

- macOS 12 or later
- Xcode 15 or later
- iOS 15+ device or simulator (for the iOS target)

### Steps

```bash
git clone https://github.com/spl90/PeezyPGP.git
cd PeezyPGP
open PeezyPGP.xcodeproj
```

In Xcode:

1. Select **PeezyPGP-macOS** or **PeezyPGP-iOS** from the scheme picker
2. Choose your destination (Mac / Simulator / physical device)
3. Press **Cmd+R** to build and run

No package manager setup, no `pod install`, no `swift package resolve`. The project has zero external dependencies — open and build.

> **Secure Enclave note:** Hardware-backed key storage requires a physical device. Simulator builds fall back to software-only Keychain protection.

### Running Tests

```
Cmd+U  — run all tests in Xcode
```

The test suite covers Ed25519 key generation, signing, verification, edge cases (wrong key, modified message, empty message), and performance benchmarks.

---

## Project Structure

```
PeezyPGP/
├── Sources/
│   ├── App/
│   │   └── PeezyPGPApp.swift            # Entry point, AppState, ContentView, SidebarView
│   ├── Crypto/
│   │   ├── Memory/
│   │   │   └── SecureBytes.swift        # Zeroing byte buffer
│   │   ├── OpenPGP/
│   │   │   ├── Armor/
│   │   │   │   └── ArmorCodec.swift     # ASCII armor encode/decode, CRC-24
│   │   │   ├── OpenPGPEngine.swift      # Key generation, encrypt, decrypt, sign, verify
│   │   │   └── Packets/
│   │   │       ├── PacketIO.swift       # Packet reader/writer
│   │   │       └── PacketTypes.swift    # RFC 9580 packet type definitions
│   │   └── Primitives/
│   │       ├── AES256Operations.swift   # AES-256-GCM
│   │       ├── Ed25519Operations.swift  # Ed25519 sign / verify
│   │       ├── HKDFOperations.swift     # HKDF-SHA-256
│   │       └── X25519Operations.swift  # X25519 ECDH + AES key wrap
│   ├── Platform/
│   │   └── macOS/
│   │       └── MacMenuCommands.swift    # macOS menu bar commands
│   ├── Presentation/
│   │   └── Views/
│   │       ├── Encrypt/
│   │       │   └── EncryptDecryptViews.swift
│   │       ├── Keys/
│   │       │   ├── KeyGenerationView.swift
│   │       │   └── KeyListView.swift
│   │       ├── Settings/
│   │       │   └── SettingsView.swift
│   │       └── Sign/
│   │           └── SignVerifyViews.swift
│   └── Storage/
│       ├── KeychainManager.swift        # Keychain CRUD
│       └── SecureEnclaveManager.swift  # Secure Enclave P-256 key wrapping
├── Tests/
│   └── CryptoTests/
│       └── Ed25519Tests.swift           # Unit + performance tests
├── Configuration/
│   ├── Info.plist
│   └── PeezyPGP.entitlements
├── Documentation/
│   ├── TECHNICAL_ARCHITECTURE.md       # Algorithm rationale and data flow diagrams
│   ├── SECURITY_HARDENING_ROADMAP.md   # Planned security improvements
│   └── APP_STORE_COMPLIANCE.md         # Export compliance and App Review notes
└── project.yml                         # XcodeGen project spec
```

---

## Encryption Flow

```
Input: plaintext + recipient public key
           │
           ├── 1. Generate 256-bit session key  (SecRandomCopyBytes)
           │
           ├── 2. ECDH Key Agreement
           │       ephemeral X25519 keypair generated fresh
           │       shared = X25519(ephemeral_priv, recipient_pub)
           │       kek = HKDF-SHA256(shared, info = ephemeral || recipient || fingerprint)
           │
           ├── 3. Wrap session key with kek  (AES Key Wrap)
           │
           ├── 4. Encrypt plaintext with session key  (AES-256-GCM)
           │
           ├── 5. Assemble OpenPGP packets
           │       PKESK — version, recipient ID, ephemeral pub, wrapped session key
           │       SEIPD v2 — version, algo, AEAD, nonce || ciphertext || tag
           │
           └── 6. ASCII Armor output
```

After each operation: session key, ephemeral private key, shared secret, and ECDH KEK are explicitly zeroed via `SecureBytes.zeroAndDeallocate()`.

---

## Roadmap

| Phase | Feature | Status |
|-------|---------|--------|
| v1.0 | Ed25519 + X25519 key generation | Done |
| v1.0 | AES-256-GCM encrypt / decrypt | Done |
| v1.0 | Ed25519 sign / verify | Done |
| v1.0 | Secure Enclave + Keychain storage | Done |
| v1.0 | Biometric authentication | Done |
| v2.0 | Guard pages + memory canaries | Planned |
| v2.0 | Jailbreak / debugger detection | Planned |
| v2.0 | Side-channel mitigations | Planned |
| v3.0 | Shamir's Secret Sharing key backup | Planned |
| v3.0 | QR code air-gapped key transfer | Planned |
| Future | Hybrid X25519 + Kyber (post-quantum) | Research |

---

## License

MIT — see [LICENSE](LICENSE).
