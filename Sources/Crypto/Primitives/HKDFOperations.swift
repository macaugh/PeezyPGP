// HKDFOperations.swift
// PeezyPGP - Privacy-First OpenPGP
//
// HKDF (HMAC-based Key Derivation Function) per RFC 5869
// Used for deriving symmetric keys from shared secrets

import Foundation
import CryptoKit

/// HKDF key derivation operations
public enum HKDFOperations {

    // MARK: - HKDF-SHA256

    /// Derive a key using HKDF-SHA256
    /// - Parameters:
    ///   - inputKeyMaterial: The input keying material (IKM)
    ///   - salt: Optional salt value (if nil, uses zero-filled salt)
    ///   - info: Context and application-specific info
    ///   - outputLength: Desired output length in bytes (max 255 * 32 = 8160)
    /// - Returns: Derived key material
    public static func deriveKey(
        inputKeyMaterial: SecureBytes,
        salt: Data?,
        info: Data,
        outputLength: Int
    ) throws -> SecureBytes {
        guard outputLength > 0 && outputLength <= 255 * SHA256.byteCount else {
            throw CryptoError.keyDerivationFailed
        }

        let ikmData = inputKeyMaterial.toData()
        defer {
            var mutableIkm = ikmData
            mutableIkm.zero()
        }

        let symmetricKey = SymmetricKey(data: ikmData)
        let saltData = salt ?? Data(repeating: 0, count: SHA256.byteCount)

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: saltData,
            info: info,
            outputByteCount: outputLength
        )

        return derivedKey.withUnsafeBytes { buffer in
            SecureBytes(bytes: Array(buffer))
        }
    }

    /// Derive a key using HKDF-SHA512
    /// - Parameters:
    ///   - inputKeyMaterial: The input keying material (IKM)
    ///   - salt: Optional salt value (if nil, uses zero-filled salt)
    ///   - info: Context and application-specific info
    ///   - outputLength: Desired output length in bytes (max 255 * 64 = 16320)
    /// - Returns: Derived key material
    public static func deriveKeySHA512(
        inputKeyMaterial: SecureBytes,
        salt: Data?,
        info: Data,
        outputLength: Int
    ) throws -> SecureBytes {
        guard outputLength > 0 && outputLength <= 255 * SHA512.byteCount else {
            throw CryptoError.keyDerivationFailed
        }

        let ikmData = inputKeyMaterial.toData()
        defer {
            var mutableIkm = ikmData
            mutableIkm.zero()
        }

        let symmetricKey = SymmetricKey(data: ikmData)
        let saltData = salt ?? Data(repeating: 0, count: SHA512.byteCount)

        let derivedKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: saltData,
            info: info,
            outputByteCount: outputLength
        )

        return derivedKey.withUnsafeBytes { buffer in
            SecureBytes(bytes: Array(buffer))
        }
    }

    // MARK: - OpenPGP-Specific KDF

    /// Derive encryption key for OpenPGP v6 SEIPD (Symmetrically Encrypted Integrity Protected Data)
    /// Per RFC 9580 Section 5.13.2
    /// - Parameters:
    ///   - sessionKey: The session key (from PKESK decryption)
    ///   - salt: 32-byte salt from SEIPD packet
    /// - Returns: Tuple of (message key, nonce/IV) for AEAD encryption
    public static func deriveOpenPGPMessageKey(
        sessionKey: SecureBytes,
        salt: Data
    ) throws -> (messageKey: SecureBytes, nonce: Data) {
        guard salt.count == 32 else {
            throw CryptoError.keyDerivationFailed
        }

        // Info string per RFC 9580
        let info = "OpenPGP SEIPD v2".data(using: .utf8)!

        // Derive 32 + 12 = 44 bytes (key + nonce)
        let derived = try deriveKey(
            inputKeyMaterial: sessionKey,
            salt: salt,
            info: info,
            outputLength: 44
        )

        let derivedBytes = derived.toBytes()
        defer {
            var mutableBytes = derivedBytes
            mutableBytes.zero()
        }

        let messageKey = SecureBytes(bytes: Array(derivedBytes.prefix(32)))
        let nonce = Data(derivedBytes.suffix(12))

        return (messageKey, nonce)
    }
}

// MARK: - SHA2 Hashing Operations

public enum SHA2Operations {

    /// Compute SHA-256 hash
    /// - Parameter data: Data to hash
    /// - Returns: 32-byte hash
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Compute SHA-512 hash
    /// - Parameter data: Data to hash
    /// - Returns: 64-byte hash
    public static func sha512(_ data: Data) -> Data {
        let digest = SHA512.hash(data: data)
        return Data(digest)
    }

    /// Compute SHA-256 hash of SecureBytes
    /// - Parameter secureBytes: SecureBytes to hash
    /// - Returns: 32-byte hash
    public static func sha256(_ secureBytes: SecureBytes) -> Data {
        secureBytes.withUnsafeBytes { buffer in
            let digest = SHA256.hash(data: buffer)
            return Data(digest)
        }
    }

    /// Compute SHA-512 hash of SecureBytes
    /// - Parameter secureBytes: SecureBytes to hash
    /// - Returns: 64-byte hash
    public static func sha512(_ secureBytes: SecureBytes) -> Data {
        secureBytes.withUnsafeBytes { buffer in
            let digest = SHA512.hash(data: buffer)
            return Data(digest)
        }
    }

    /// Compute incremental SHA-256 hash
    /// Useful for large data or streaming
    public final class SHA256Hasher {
        private var hasher = SHA256()

        public init() {}

        public func update(_ data: Data) {
            hasher.update(data: data)
        }

        public func update(_ bytes: [UInt8]) {
            hasher.update(data: bytes)
        }

        public func finalize() -> Data {
            return Data(hasher.finalize())
        }
    }

    /// Compute incremental SHA-512 hash
    public final class SHA512Hasher {
        private var hasher = SHA512()

        public init() {}

        public func update(_ data: Data) {
            hasher.update(data: data)
        }

        public func update(_ bytes: [UInt8]) {
            hasher.update(data: bytes)
        }

        public func finalize() -> Data {
            return Data(hasher.finalize())
        }
    }
}
