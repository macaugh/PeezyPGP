# PeezyPGP Technical Architecture

## Cryptographic Design Rationale

### Algorithm Selection

#### Signing: Ed25519 (RFC 8032)

**Why Ed25519:**
- 128-bit security level
- Deterministic signatures (no random nonce required)
- Fast: ~15,000 signatures/sec on modern hardware
- Small keys (32 bytes) and signatures (64 bytes)
- Immune to timing attacks in reference implementation
- Widely audited and battle-tested

**Alternatives Considered:**
- RSA-4096: Larger keys, slower, implementation complexity
- ECDSA P-256: Requires secure random for each signature
- Ed448: 224-bit security overkill, less hardware support

#### Key Agreement: X25519 (RFC 7748)

**Why X25519:**
- 128-bit security level
- Constant-time by design
- Simple implementation reduces attack surface
- Pairs naturally with Ed25519
- Strong adoption in Signal, WireGuard, TLS 1.3

**Implementation:**
```
ECDH Output = X25519(private_key, peer_public_key)
Session Key = HKDF-SHA256(ECDH_Output, salt=ephemeral||recipient, info="OpenPGP")
```

#### Symmetric Encryption: AES-256-GCM

**Why AES-256-GCM:**
- 256-bit security level
- AEAD: Provides confidentiality + integrity
- Hardware acceleration on all Apple Silicon
- NIST approved, widely audited
- CryptoKit native support

**Why not AES-256-CBC:**
- No authentication (requires separate HMAC)
- Padding oracle attacks possible
- More implementation complexity

**Why not ChaCha20-Poly1305:**
- Excellent algorithm, but AES-GCM has hardware accel
- GCM performance on Apple Silicon is exceptional

#### Hash Functions: SHA-256/SHA-512

**Usage:**
- SHA-256: Fingerprints, HKDF, general hashing
- SHA-512: Large data hashing (better performance on 64-bit)

**Why SHA-2 family:**
- No known practical attacks
- NIST approved
- Hardware acceleration available
- CryptoKit native support

**Why not SHA-3:**
- Slower in software
- Less hardware support
- SHA-2 remains secure

#### Key Derivation: Argon2id (RFC 9106)

**Why Argon2id:**
- Winner of Password Hashing Competition
- Memory-hard: Resists GPU/ASIC attacks
- Combines Argon2i (side-channel resistant) and Argon2d (GPU resistant)
- Configurable memory/time parameters

**Parameters (Mobile):**
```
Memory: 64 MiB (m=16, memory = 2^16 KiB)
Iterations: 4 (t=4)
Parallelism: 4 (p=4)
Tag length: 32 bytes
```

**Parameters (Desktop):**
```
Memory: 512 MiB (m=19, memory = 2^19 KiB)
Iterations: 3 (t=3)
Parallelism: 4 (p=4)
Tag length: 32 bytes
```

---

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Key Hierarchy                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Level 0: User Passphrase                                                   │
│  └─── Memorized by user, never stored                                       │
│                                                                             │
│  Level 1: Key Encryption Key (KEK)                                          │
│  └─── Derived from passphrase via Argon2id                                  │
│  └─── Never persisted                                                       │
│                                                                             │
│  Level 2: OpenPGP Private Keys (encrypted)                                  │
│  └─── Ed25519 signing key                                                   │
│  └─── X25519 encryption key                                                 │
│  └─── Encrypted with KEK + AES-256-GCM                                      │
│  └─── Stored in Keychain                                                    │
│                                                                             │
│  Level 3: Secure Enclave KEK (optional)                                     │
│  └─── P-256 key in Secure Enclave                                           │
│  └─── Wraps Level 2 encrypted keys                                          │
│  └─── Adds hardware binding                                                 │
│                                                                             │
│  Level 4: Session Keys (ephemeral)                                          │
│  └─── Generated per message                                                 │
│  └─── 256-bit random                                                        │
│  └─── Encrypted to recipient via ECDH                                       │
│  └─── Never persisted                                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagrams

### Key Generation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Key Generation Flow                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. User Input                                                              │
│     ├─── User ID (name + email)                                             │
│     └─── Passphrase                                                         │
│                                                                             │
│  2. Key Generation                                                          │
│     ├─── Ed25519 keypair ← SecRandomCopyBytes(32)                          │
│     └─── X25519 keypair  ← SecRandomCopyBytes(32)                          │
│                                                                             │
│  3. S2K Setup                                                               │
│     ├─── Salt ← SecRandomCopyBytes(16)                                      │
│     └─── KEK = Argon2id(passphrase, salt, params)                          │
│                                                                             │
│  4. Private Key Encryption                                                  │
│     ├─── enc_signing = AES-256-GCM(signing_priv, KEK)                      │
│     └─── enc_encrypt = AES-256-GCM(encrypt_priv, KEK)                      │
│                                                                             │
│  5. Secure Enclave Wrapping (optional)                                      │
│     ├─── SE_KEK = SecureEnclave.P256.privateKey                            │
│     ├─── wrapped_signing = ECIES(enc_signing, SE_KEK.publicKey)            │
│     └─── wrapped_encrypt = ECIES(enc_encrypt, SE_KEK.publicKey)            │
│                                                                             │
│  6. Storage                                                                 │
│     └─── Keychain.store(PGPKey, ACL=biometric)                             │
│                                                                             │
│  7. Cleanup                                                                 │
│     ├─── Zero(passphrase)                                                  │
│     ├─── Zero(KEK)                                                         │
│     ├─── Zero(signing_priv)                                                │
│     └─── Zero(encrypt_priv)                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Message Encryption

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Message Encryption Flow                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input:                                                                     │
│     ├─── Plaintext message                                                  │
│     └─── Recipient public key                                               │
│                                                                             │
│  1. Session Key Generation                                                  │
│     └─── session_key ← SecRandomCopyBytes(32)                              │
│                                                                             │
│  2. ECDH Key Agreement                                                      │
│     ├─── ephemeral_priv ← SecRandomCopyBytes(32)                           │
│     ├─── ephemeral_pub = X25519.publicKey(ephemeral_priv)                  │
│     └─── shared = X25519(ephemeral_priv, recipient_pub)                    │
│                                                                             │
│  3. KEK Derivation                                                          │
│     └─── kek = HKDF-SHA256(shared, info=ephemeral||recipient||fingerprint) │
│                                                                             │
│  4. Session Key Wrapping                                                    │
│     └─── wrapped_key = AES-KeyWrap(session_key, kek)                       │
│                                                                             │
│  5. Message Encryption                                                      │
│     ├─── nonce ← SecRandomCopyBytes(12)                                    │
│     └─── ciphertext = AES-256-GCM(plaintext, session_key, nonce)           │
│                                                                             │
│  6. Packet Assembly                                                         │
│     ├─── PKESK = {version, recipient_id, ephemeral_pub, wrapped_key}       │
│     └─── SEIPD = {version, algo, aead_algo, nonce||ciphertext||tag}        │
│                                                                             │
│  7. Output                                                                  │
│     └─── ASCII Armor(PKESK || SEIPD)                                       │
│                                                                             │
│  8. Cleanup                                                                 │
│     ├─── Zero(session_key)                                                 │
│     ├─── Zero(ephemeral_priv)                                              │
│     ├─── Zero(shared)                                                      │
│     └─── Zero(kek)                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Message Decryption

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Message Decryption Flow                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Input:                                                                     │
│     ├─── Encrypted message (ASCII armor)                                    │
│     ├─── Recipient private key (encrypted)                                  │
│     └─── Passphrase                                                         │
│                                                                             │
│  1. Armor Decode                                                            │
│     ├─── Verify CRC24                                                       │
│     └─── Parse packets (PKESK, SEIPD)                                       │
│                                                                             │
│  2. Private Key Unlock                                                      │
│     ├─── Biometric authentication (if configured)                          │
│     ├─── SE unwrap (if Secure Enclave used)                                │
│     ├─── KEK = Argon2id(passphrase, stored_salt)                           │
│     └─── decrypt_priv = AES-256-GCM.open(enc_priv, KEK)                    │
│                                                                             │
│  3. Session Key Recovery                                                    │
│     ├─── shared = X25519(decrypt_priv, ephemeral_pub)                      │
│     ├─── kek = HKDF-SHA256(shared, info=...)                               │
│     └─── session_key = AES-KeyUnwrap(wrapped_key, kek)                     │
│                                                                             │
│  4. Message Decryption                                                      │
│     └─── plaintext = AES-256-GCM.open(ciphertext, session_key, nonce)      │
│                                                                             │
│  5. Packet Parsing                                                          │
│     └─── Extract literal data from decrypted packets                       │
│                                                                             │
│  6. Output                                                                  │
│     └─── Plaintext message                                                  │
│                                                                             │
│  7. Cleanup                                                                 │
│     ├─── Zero(passphrase)                                                  │
│     ├─── Zero(KEK)                                                         │
│     ├─── Zero(decrypt_priv)                                                │
│     ├─── Zero(shared)                                                      │
│     ├─── Zero(kek)                                                         │
│     └─── Zero(session_key)                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Security Boundaries                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    App Process (Sandboxed)                          │   │
│  │                                                                      │   │
│  │   Trust Level: LOW                                                   │   │
│  │   - SwiftUI views                                                    │   │
│  │   - View models                                                      │   │
│  │   - User input handling                                              │   │
│  │   - Clipboard operations                                             │   │
│  │                                                                      │   │
│  │   ┌───────────────────────────────────────────────────────────────┐ │   │
│  │   │               Crypto Module (Isolated)                        │ │   │
│  │   │                                                               │ │   │
│  │   │   Trust Level: MEDIUM                                         │ │   │
│  │   │   - OpenPGP packet handling                                   │ │   │
│  │   │   - Key serialization                                         │ │   │
│  │   │   - Armor encoding/decoding                                   │ │   │
│  │   │                                                               │ │   │
│  │   │   ┌───────────────────────────────────────────────────────┐  │ │   │
│  │   │   │           CryptoKit (Apple Framework)                 │  │ │   │
│  │   │   │                                                       │  │ │   │
│  │   │   │   Trust Level: HIGH                                   │  │ │   │
│  │   │   │   - Ed25519 operations                                │  │ │   │
│  │   │   │   - X25519 operations                                 │  │ │   │
│  │   │   │   - AES-GCM operations                                │  │ │   │
│  │   │   │   - SHA-256/512 operations                            │  │ │   │
│  │   │   │   - HKDF operations                                   │  │ │   │
│  │   │   │   - SecRandomCopyBytes                                │  │ │   │
│  │   │   └───────────────────────────────────────────────────────┘  │ │   │
│  │   └───────────────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                              IPC/API Boundary                               │
│                                    │                                        │
│  ┌─────────────────────────────────▼───────────────────────────────────┐   │
│  │                    Keychain Services (Daemon)                       │   │
│  │                                                                      │   │
│  │   Trust Level: HIGH                                                  │   │
│  │   - Encrypted key storage                                            │   │
│  │   - Access control enforcement                                       │   │
│  │   - Biometric validation                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                              Hardware Boundary                              │
│                                    │                                        │
│  ┌─────────────────────────────────▼───────────────────────────────────┐   │
│  │                    Secure Enclave (Hardware)                        │   │
│  │                                                                      │   │
│  │   Trust Level: HIGHEST                                               │   │
│  │   - P-256 key operations                                             │   │
│  │   - Key never exportable                                             │   │
│  │   - Hardware-isolated                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## API Surface Minimization

### External APIs Used

| API | Purpose | Risk Level |
|-----|---------|------------|
| CryptoKit | All crypto operations | Low (Apple) |
| Security.framework | Keychain, SecRandom | Low (Apple) |
| LocalAuthentication | Biometrics | Low (Apple) |
| SwiftUI | User interface | Low (Apple) |
| Foundation | Basic data types | Low (Apple) |

### APIs Explicitly NOT Used

| API | Why Excluded |
|-----|--------------|
| URLSession | No network access |
| Network.framework | No network access |
| CloudKit | No cloud sync |
| Analytics | No telemetry |
| AdSupport | No advertising |
| CoreLocation | No location |
| Contacts | No address book |
| Photos | No photo access |

---

## Build Configuration

### Compiler Flags

```
// Swift settings
SWIFT_COMPILATION_MODE = wholemodule
SWIFT_OPTIMIZATION_LEVEL = -O  // Release
SWIFT_OPTIMIZATION_LEVEL = -Onone  // Debug

// Security hardening
ENABLE_HARDENED_RUNTIME = YES
CODE_SIGN_INJECT_BASE_ENTITLEMENTS = YES

// Stack protection
OTHER_CFLAGS = -fstack-protector-strong
```

### Link Settings

```
// No unnecessary frameworks
DEAD_CODE_STRIPPING = YES
STRIP_INSTALLED_PRODUCT = YES

// Position Independent Executable
ENABLE_BITCODE = NO  // Deprecated, use -pie
OTHER_LDFLAGS = -pie
```

---

## Testing Strategy

### Unit Tests
- All crypto primitives
- Packet parsing/serialization
- Armor encoding/decoding
- S2K derivation

### Integration Tests
- Full encrypt/decrypt roundtrip
- Full sign/verify roundtrip
- Key generation and storage
- Key import/export

### Security Tests
- No network calls (proxy verification)
- Memory zeroing (instrumentation)
- Keychain ACL enforcement
- Biometric bypass attempts

### Fuzzing Targets
- Armor decoder
- Packet parser
- MPI decoder
- S2K parser
