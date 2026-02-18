// Ed25519Operations.swift
// PeezyPGP - Privacy-First OpenPGP
//
// Ed25519 digital signatures per RFC 8032
// Used for OpenPGP signing keys (algorithm ID 22 in RFC 9580)

import Foundation
import CryptoKit

/// Ed25519 signing operations
/// All methods are stateless and thread-safe
public enum Ed25519Operations {

    // MARK: - Constants

    /// Ed25519 private key size in bytes
    public static let privateKeySize = 32

    /// Ed25519 public key size in bytes
    public static let publicKeySize = 32

    /// Ed25519 signature size in bytes
    public static let signatureSize = 64

    // MARK: - Key Generation

    /// Generate a new Ed25519 key pair
    /// - Returns: Tuple of (privateKey, publicKey) as SecureBytes
    /// - Throws: CryptoError if generation fails
    public static func generateKeyPair() throws -> (privateKey: SecureBytes, publicKey: SecureBytes) {
        let privateKey = Curve25519.Signing.PrivateKey()

        let privateKeyBytes = SecureBytes(data: privateKey.rawRepresentation)
        let publicKeyBytes = SecureBytes(data: privateKey.publicKey.rawRepresentation)

        return (privateKeyBytes, publicKeyBytes)
    }

    /// Derive public key from private key
    /// - Parameter privateKey: 32-byte Ed25519 private key
    /// - Returns: 32-byte public key
    /// - Throws: CryptoError if key is invalid
    public static func derivePublicKey(from privateKey: SecureBytes) throws -> SecureBytes {
        guard privateKey.count == privateKeySize else {
            throw CryptoError.invalidKeySize(expected: privateKeySize, actual: privateKey.count)
        }

        let privateKeyData = privateKey.toData()
        defer {
            var mutableData = privateKeyData
            mutableData.zero()
        }

        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return SecureBytes(data: signingKey.publicKey.rawRepresentation)
    }

    // MARK: - Signing

    /// Sign a message using Ed25519
    /// - Parameters:
    ///   - message: Data to sign
    ///   - privateKey: 32-byte Ed25519 private key
    /// - Returns: 64-byte signature
    /// - Throws: CryptoError on failure
    public static func sign(message: Data, privateKey: SecureBytes) throws -> Data {
        guard privateKey.count == privateKeySize else {
            throw CryptoError.invalidKeySize(expected: privateKeySize, actual: privateKey.count)
        }

        let privateKeyData = privateKey.toData()
        defer {
            var mutableData = privateKeyData
            mutableData.zero()
        }

        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let signature = try signingKey.signature(for: message)

        return signature
    }

    /// Sign a hash digest directly (for OpenPGP signature packets)
    /// - Parameters:
    ///   - digest: Hash digest to sign
    ///   - privateKey: 32-byte Ed25519 private key
    /// - Returns: 64-byte signature
    /// - Throws: CryptoError on failure
    /// - Note: Ed25519 includes its own hashing, so this signs the digest as-is
    public static func signDigest(_ digest: Data, privateKey: SecureBytes) throws -> Data {
        // Ed25519 signs messages directly - the digest IS the message
        return try sign(message: digest, privateKey: privateKey)
    }

    // MARK: - Verification

    /// Verify an Ed25519 signature
    /// - Parameters:
    ///   - signature: 64-byte signature
    ///   - message: Original message data
    ///   - publicKey: 32-byte Ed25519 public key
    /// - Returns: true if signature is valid
    public static func verify(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard publicKey.count == publicKeySize else {
            return false
        }

        guard signature.count == signatureSize else {
            return false
        }

        do {
            let verifyingKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return verifyingKey.isValidSignature(signature, for: message)
        } catch {
            return false
        }
    }

    /// Verify an Ed25519 signature with SecureBytes public key
    /// - Parameters:
    ///   - signature: 64-byte signature
    ///   - message: Original message data
    ///   - publicKey: 32-byte Ed25519 public key as SecureBytes
    /// - Returns: true if signature is valid
    public static func verify(signature: Data, message: Data, publicKey: SecureBytes) -> Bool {
        return verify(signature: signature, message: message, publicKey: publicKey.toData())
    }
}

// MARK: - CryptoError

/// Errors specific to cryptographic operations
public enum CryptoError: Error, LocalizedError {
    case invalidKeySize(expected: Int, actual: Int)
    case invalidSignatureSize(expected: Int, actual: Int)
    case keyGenerationFailed
    case signingFailed(underlying: Error)
    case verificationFailed
    case encryptionFailed(underlying: Error)
    case decryptionFailed(underlying: Error)
    case invalidCiphertext
    case invalidNonce
    case keyDerivationFailed
    case unsupportedAlgorithm(String)
    case invalidPacket(String)
    case armorFormatError(String)
    case checksumMismatch
    case integrityCheckFailed

    public var errorDescription: String? {
        switch self {
        case .invalidKeySize(let expected, let actual):
            return "Invalid key size: expected \(expected) bytes, got \(actual)"
        case .invalidSignatureSize(let expected, let actual):
            return "Invalid signature size: expected \(expected) bytes, got \(actual)"
        case .keyGenerationFailed:
            return "Key generation failed"
        case .signingFailed(let error):
            return "Signing failed: \(error.localizedDescription)"
        case .verificationFailed:
            return "Signature verification failed"
        case .encryptionFailed(let error):
            return "Encryption failed: \(error.localizedDescription)"
        case .decryptionFailed(let error):
            return "Decryption failed: \(error.localizedDescription)"
        case .invalidCiphertext:
            return "Invalid ciphertext format"
        case .invalidNonce:
            return "Invalid nonce/IV"
        case .keyDerivationFailed:
            return "Key derivation failed"
        case .unsupportedAlgorithm(let name):
            return "Unsupported algorithm: \(name)"
        case .invalidPacket(let reason):
            return "Invalid OpenPGP packet: \(reason)"
        case .armorFormatError(let reason):
            return "ASCII armor format error: \(reason)"
        case .checksumMismatch:
            return "Checksum mismatch - data may be corrupted"
        case .integrityCheckFailed:
            return "Integrity check failed - data may have been tampered with"
        }
    }
}
