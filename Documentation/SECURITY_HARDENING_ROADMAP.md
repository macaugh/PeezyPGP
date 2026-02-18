# PeezyPGP Security Hardening Roadmap

## Current Security Posture (v1.0)

### Implemented Protections

| Layer | Protection | Status |
|-------|-----------|--------|
| Network | Zero network entitlements | ✅ Complete |
| Storage | Apple Keychain | ✅ Complete |
| Storage | Secure Enclave KEK | ✅ Complete |
| Auth | Biometric gating | ✅ Complete |
| Memory | SecureBytes with explicit zeroing | ✅ Complete |
| Crypto | CryptoKit (Apple's audited implementation) | ✅ Complete |
| S2K | Argon2id support | ✅ Complete |

---

## Phase 2: Advanced Memory Protection

### 2.1 Memory Locking Enhancement

**Current:** Best-effort `mlock()` calls
**Target:** Guaranteed locked memory allocation

```swift
// Future: Custom allocator with guaranteed locking
final class LockedMemoryAllocator {
    private var lockedRegion: UnsafeMutableRawPointer?
    private let size: Int

    init(size: Int) throws {
        // Allocate with mmap and MAP_LOCKED
        let ptr = mmap(
            nil,
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
            -1,
            0
        )
        guard ptr != MAP_FAILED else {
            throw MemoryError.lockFailed
        }
        self.lockedRegion = ptr
        self.size = size
    }

    deinit {
        // Secure wipe before unmapping
        memset_s(lockedRegion!, size, 0, size)
        munmap(lockedRegion, size)
    }
}
```

### 2.2 Guard Pages

Add guard pages around sensitive memory regions:

```swift
// Allocate with guard pages before and after
let guardedRegion = GuardedMemory(size: 4096)
// Access violation if overflow/underflow occurs
```

### 2.3 Canary Values

Implement stack canaries for sensitive operations:

```swift
func decryptWithCanary(ciphertext: Data, key: SecureBytes) throws -> Data {
    let canary = SecureBytes(randomBytes: 32)
    defer {
        guard canary.isValid else {
            fatalError("Stack corruption detected")
        }
    }
    // ... decryption logic
}
```

---

## Phase 3: Anti-Tampering

### 3.1 Jailbreak Detection

```swift
enum JailbreakDetector {
    static func isCompromised() -> Bool {
        // Check for suspicious paths
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/private/var/lib/apt",
            "/private/var/stash",
            "/usr/sbin/sshd",
            "/usr/bin/ssh"
        ]

        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        // Check if we can write outside sandbox
        let testPath = "/private/jailbreak_test"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // Should not be able to write here
        } catch {
            // Expected - we should not have write access
        }

        // Check for suspicious URL schemes
        if UIApplication.shared.canOpenURL(URL(string: "cydia://")!) {
            return true
        }

        return false
    }
}
```

### 3.2 Debugger Detection

```swift
func isDebuggerAttached() -> Bool {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

    let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    guard result == 0 else { return false }

    return (info.kp_proc.p_flag & P_TRACED) != 0
}
```

### 3.3 Binary Integrity

Verify app binary hasn't been modified:

```swift
func verifyBinaryIntegrity() -> Bool {
    // Check code signature
    var staticCode: SecStaticCode?
    let mainBundle = Bundle.main.bundleURL as CFURL

    guard SecStaticCodeCreateWithPath(mainBundle, [], &staticCode) == errSecSuccess,
          let code = staticCode else {
        return false
    }

    let requirement = "anchor apple generic"
    var requirementRef: SecRequirement?
    guard SecRequirementCreateWithString(requirement as CFString, [], &requirementRef) == errSecSuccess,
          let req = requirementRef else {
        return false
    }

    return SecStaticCodeCheckValidity(code, [], req) == errSecSuccess
}
```

---

## Phase 4: Side-Channel Mitigations

### 4.1 Constant-Time Comparisons

Already implemented via CryptoKit. Additional hardening:

```swift
// Ensure all secret comparisons use constant-time
extension SecureBytes {
    func constantTimePrefix(_ length: Int) -> Bool {
        guard count >= length else { return false }
        // Ensure comparison takes same time regardless of match position
        var result: UInt8 = 0
        withUnsafeBytes { buffer in
            for i in 0..<length {
                result |= buffer[i]
            }
        }
        return result != 0
    }
}
```

### 4.2 Blinding for Sensitive Operations

For any operations not covered by CryptoKit:

```swift
// Blind input before processing
func blindedOperation<T>(input: SecureBytes, operation: (SecureBytes) -> T) -> T {
    let blind = SecureBytes(randomBytes: input.count)
    let blinded = input.xor(with: blind)
    defer { blinded.zeroAndDeallocate() }

    let result = operation(blinded)
    // Unblind if necessary
    return result
}
```

### 4.3 Timing Attack Mitigation

Add random delays to mask timing:

```swift
func constantTimeDelay(minMicroseconds: UInt32 = 1000, maxMicroseconds: UInt32 = 5000) {
    var delay: UInt32 = 0
    _ = SecRandomCopyBytes(kSecRandomDefault, 4, &delay)
    let microseconds = minMicroseconds + (delay % (maxMicroseconds - minMicroseconds))
    usleep(microseconds)
}
```

---

## Phase 5: Audit Trail

### 5.1 Secure Logging

```swift
final class SecureAuditLog {
    private let maxEntries = 1000
    private var entries: [AuditEntry] = []
    private let lock = NSLock()

    struct AuditEntry: Codable {
        let timestamp: Date
        let action: String
        let keyID: String?
        let success: Bool
        // No sensitive data logged
    }

    func log(action: String, keyID: String? = nil, success: Bool = true) {
        lock.lock()
        defer { lock.unlock() }

        let entry = AuditEntry(
            timestamp: Date(),
            action: action,
            keyID: keyID?.prefix(8).description,  // Only log partial key ID
            success: success
        )

        entries.append(entry)

        // Rotate old entries
        if entries.count > maxEntries {
            entries.removeFirst(entries.count - maxEntries)
        }
    }
}
```

### 5.2 Failed Authentication Tracking

```swift
final class AuthenticationMonitor {
    private var failedAttempts: [String: Int] = [:]
    private var lockoutUntil: [String: Date] = [:]

    private let maxAttempts = 5
    private let lockoutDuration: TimeInterval = 300 // 5 minutes

    func recordFailure(for keyID: String) {
        failedAttempts[keyID, default: 0] += 1

        if failedAttempts[keyID]! >= maxAttempts {
            lockoutUntil[keyID] = Date().addingTimeInterval(lockoutDuration)
        }
    }

    func isLockedOut(_ keyID: String) -> Bool {
        guard let lockout = lockoutUntil[keyID] else { return false }
        if Date() > lockout {
            lockoutUntil.removeValue(forKey: keyID)
            failedAttempts.removeValue(forKey: keyID)
            return false
        }
        return true
    }
}
```

---

## Phase 6: Key Ceremony Support

### 6.1 Multi-Party Key Generation

Support for Shamir's Secret Sharing:

```swift
// Split key into n shares, requiring k to reconstruct
func splitKey(key: SecureBytes, shares n: Int, threshold k: Int) throws -> [SecureBytes] {
    // Implement Shamir's Secret Sharing
    // Each share is a point (x, y) on a polynomial
}

func reconstructKey(from shares: [SecureBytes]) throws -> SecureBytes {
    // Lagrange interpolation to recover secret
}
```

### 6.2 Air-Gapped Export

QR code export for truly air-gapped transfers:

```swift
func generateKeyQRCodes(key: PGPKey) -> [UIImage] {
    // Split armored key into chunks
    // Generate QR code for each chunk
    // Include sequence numbers and checksums
}
```

---

## Phase 7: Post-Quantum Preparation

### 7.1 Hybrid Key Exchange

Prepare for post-quantum algorithms:

```swift
// Hybrid: X25519 + Kyber
struct HybridKeyExchange {
    let classicalShared: SecureBytes  // X25519
    let pqShared: SecureBytes         // Kyber (when available)

    var combinedSecret: SecureBytes {
        // KDF(classical || pq)
        return HKDFOperations.deriveKey(
            inputKeyMaterial: SecureBytes(bytes: classicalShared.toBytes() + pqShared.toBytes()),
            salt: nil,
            info: "hybrid-key-exchange".data(using: .utf8)!,
            outputLength: 32
        )
    }
}
```

### 7.2 Algorithm Agility

Design for easy algorithm replacement:

```swift
protocol KeyExchangeAlgorithm {
    func generateKeyPair() throws -> (privateKey: SecureBytes, publicKey: Data)
    func sharedSecret(privateKey: SecureBytes, peerPublicKey: Data) throws -> SecureBytes
}

// Easy to add new implementations
struct X25519KeyExchange: KeyExchangeAlgorithm { }
struct KyberKeyExchange: KeyExchangeAlgorithm { }  // Future
struct HybridKeyExchange: KeyExchangeAlgorithm { } // Future
```

---

## Implementation Priority

| Phase | Priority | Effort | Impact |
|-------|----------|--------|--------|
| Phase 2: Memory | High | Medium | High |
| Phase 3: Anti-Tamper | Medium | Medium | Medium |
| Phase 4: Side-Channel | Medium | High | Medium |
| Phase 5: Audit | Low | Low | Low |
| Phase 6: Ceremony | Low | High | Niche |
| Phase 7: Post-Quantum | Future | High | Future-proof |

---

## Security Audit Recommendations

Before v2.0 release, engage:

1. **Code Audit**: NCC Group, Trail of Bits, or Cure53
2. **Penetration Testing**: Focus on:
   - Key extraction attempts
   - Memory forensics
   - Side-channel analysis
3. **Formal Verification**: Consider for core crypto paths

---

## Continuous Security

1. **Dependency Monitoring**: No dependencies = no supply chain risk
2. **Apple Security Updates**: Track CryptoKit changes
3. **CVE Monitoring**: Watch for relevant vulnerabilities
4. **Fuzzing**: Implement continuous fuzzing for parsers
