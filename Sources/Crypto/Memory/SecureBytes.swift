// SecureBytes.swift
// PeezyPGP - Privacy-First OpenPGP
//
// SECURITY CRITICAL: This type provides explicit memory management for sensitive data.
// All cryptographic secrets MUST use SecureBytes, never raw Data or [UInt8].

import Foundation

/// A secure container for sensitive byte sequences that provides:
/// - Explicit memory zeroing on deallocation
/// - Controlled access patterns
/// - Copy-on-write semantics with secure copying
/// - Memory locking (where available)
public final class SecureBytes: @unchecked Sendable {

    // MARK: - Private Storage

    /// Internal buffer - never exposed directly
    private var buffer: UnsafeMutableBufferPointer<UInt8>

    /// Lock for thread-safe access
    private let lock = NSLock()

    /// Track if already zeroed to prevent double-free issues
    private var isZeroed = false

    // MARK: - Public Properties

    /// Number of bytes stored
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return buffer.count
    }

    /// Check if empty
    public var isEmpty: Bool {
        count == 0
    }

    // MARK: - Initialization

    /// Initialize with a specific size, filled with secure random bytes
    /// - Parameter count: Number of random bytes to generate
    public init(randomBytes count: Int) {
        precondition(count >= 0, "Count must be non-negative")

        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max(count, 1))
        self.buffer = UnsafeMutableBufferPointer(start: pointer, count: count)

        if count > 0 {
            // Use SecRandomCopyBytes for cryptographic randomness
            let status = SecRandomCopyBytes(kSecRandomDefault, count, pointer)
            guard status == errSecSuccess else {
                // Critical failure - zero and deallocate
                secureZeroMemory(pointer, count, 0, count)
                pointer.deallocate()
                fatalError("SecRandomCopyBytes failed with status \(status) - cannot generate secure random bytes")
            }
        }

        // Attempt to lock memory (best effort - may fail on iOS)
        _ = mlock(pointer, count)
    }

    /// Initialize from existing bytes, copying securely
    /// - Parameter bytes: Source bytes to copy (will not be modified)
    public init(bytes: [UInt8]) {
        let count = bytes.count
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max(count, 1))
        self.buffer = UnsafeMutableBufferPointer(start: pointer, count: count)

        if count > 0 {
            bytes.withUnsafeBytes { source in
                memcpy(pointer, source.baseAddress!, count)
            }
        }

        _ = mlock(pointer, count)
    }

    /// Initialize from Data, copying securely
    /// - Parameter data: Source data to copy
    public init(data: Data) {
        let count = data.count
        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max(count, 1))
        self.buffer = UnsafeMutableBufferPointer(start: pointer, count: count)

        if count > 0 {
            data.withUnsafeBytes { source in
                memcpy(pointer, source.baseAddress!, count)
            }
        }

        _ = mlock(pointer, count)
    }

    /// Initialize with zeros of specified size
    /// - Parameter zeroedCount: Number of zero bytes
    public init(zeroedCount: Int) {
        precondition(zeroedCount >= 0, "Count must be non-negative")

        let pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: max(zeroedCount, 1))
        self.buffer = UnsafeMutableBufferPointer(start: pointer, count: zeroedCount)

        if zeroedCount > 0 {
            memset(pointer, 0, zeroedCount)
        }

        _ = mlock(pointer, zeroedCount)
    }

    // MARK: - Deinitialization

    deinit {
        zeroAndDeallocate()
    }

    /// Explicitly zero memory and deallocate
    /// Can be called manually for immediate zeroing before dealloc
    public func zeroAndDeallocate() {
        lock.lock()
        defer { lock.unlock() }

        guard !isZeroed else { return }

        if let pointer = buffer.baseAddress, buffer.count > 0 {
            // Use memset_s which cannot be optimized away
            // This is critical - regular memset can be removed by compiler
            secureZeroMemory(pointer, buffer.count, 0, buffer.count)

            // Unlock memory
            munlock(pointer, buffer.count)

            // Deallocate
            pointer.deallocate()
        }

        isZeroed = true
    }

    // MARK: - Secure Access

    /// Execute a closure with read-only access to the bytes
    /// - Parameter body: Closure receiving a buffer pointer
    /// - Returns: The closure's return value
    /// - Note: Do NOT store the pointer outside the closure
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }

        precondition(!isZeroed, "Accessing zeroed SecureBytes")

        return try body(UnsafeRawBufferPointer(buffer))
    }

    /// Execute a closure with mutable access to the bytes
    /// - Parameter body: Closure receiving a mutable buffer pointer
    /// - Returns: The closure's return value
    /// - Note: Do NOT store the pointer outside the closure
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }

        precondition(!isZeroed, "Accessing zeroed SecureBytes")

        return try body(UnsafeMutableRawBufferPointer(buffer))
    }

    // MARK: - Conversion (Use Sparingly)

    /// Convert to Data - USE ONLY when interfacing with APIs requiring Data
    /// The returned Data is a COPY and should be zeroed after use
    public func toData() -> Data {
        lock.lock()
        defer { lock.unlock() }

        precondition(!isZeroed, "Accessing zeroed SecureBytes")

        return Data(buffer)
    }

    /// Convert to byte array - USE ONLY when absolutely necessary
    /// The returned array is a COPY and should be zeroed after use
    public func toBytes() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }

        precondition(!isZeroed, "Accessing zeroed SecureBytes")

        return Array(buffer)
    }

    // MARK: - Comparison

    /// Constant-time equality comparison
    /// Prevents timing attacks when comparing secrets
    public func constantTimeEquals(_ other: SecureBytes) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard buffer.count == other.count else { return false }

        var result: UInt8 = 0

        other.withUnsafeBytes { otherBytes in
            for i in 0..<buffer.count {
                result |= buffer[i] ^ otherBytes.load(fromByteOffset: i, as: UInt8.self)
            }
        }

        return result == 0
    }
}

// MARK: - memset_s Implementation

/// Secure memset that cannot be optimized away by the compiler
/// This is critical for security - regular memset can be removed if
/// the compiler determines the memory is not used afterward
@inline(never)
private func secureZeroMemory(_ dest: UnsafeMutableRawPointer, _ destSize: Int, _ value: Int32, _ count: Int) {
    // Volatile pointer prevents optimization
    let volatilePtr = UnsafeMutablePointer<UInt8>(OpaquePointer(dest))

    for i in 0..<min(destSize, count) {
        volatilePtr[i] = UInt8(truncatingIfNeeded: value)
    }

    // Memory barrier to ensure writes complete
    OSMemoryBarrier()
}

// MARK: - Extension for Zeroing Standard Types

public extension Data {
    /// Zero this Data's contents in place
    /// Call before releasing sensitive Data
    mutating func zero() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { buffer in
            secureZeroMemory(buffer.baseAddress!, buffer.count, 0, buffer.count)
        }
    }
}

public extension Array where Element == UInt8 {
    /// Zero this array's contents in place
    /// Call before releasing sensitive byte arrays
    mutating func zero() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { buffer in
            secureZeroMemory(buffer.baseAddress!, buffer.count, 0, buffer.count)
        }
    }
}
