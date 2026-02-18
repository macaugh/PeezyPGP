// X25519Operations.swift
// PeezyPGP - Privacy-First OpenPGP
//
// X25519 Elliptic Curve Diffie-Hellman per RFC 7748
// Used for OpenPGP encryption keys (algorithm ID 25 in RFC 9580)

import Foundation
import CryptoKit

/// X25519 ECDH operations for OpenPGP encryption
/// Implements the key agreement scheme used in RFC 9580
public enum X25519Operations {

    // MARK: - Constants

    /// X25519 private key size in bytes
    public static let privateKeySize = 32

    /// X25519 public key size in bytes
    public static let publicKeySize = 32

    /// Shared secret size in bytes
    public static let sharedSecretSize = 32

    // MARK: - Key Generation

    /// Generate a new X25519 key pair
    /// - Returns: Tuple of (privateKey, publicKey) as SecureBytes
    public static func generateKeyPair() throws -> (privateKey: SecureBytes, publicKey: SecureBytes) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()

        let privateKeyBytes = SecureBytes(data: privateKey.rawRepresentation)
        let publicKeyBytes = SecureBytes(data: privateKey.publicKey.rawRepresentation)

        return (privateKeyBytes, publicKeyBytes)
    }

    /// Derive public key from private key
    /// - Parameter privateKey: 32-byte X25519 private key
    /// - Returns: 32-byte public key
    public static func derivePublicKey(from privateKey: SecureBytes) throws -> SecureBytes {
        guard privateKey.count == privateKeySize else {
            throw CryptoError.invalidKeySize(expected: privateKeySize, actual: privateKey.count)
        }

        let privateKeyData = privateKey.toData()
        defer {
            var mutableData = privateKeyData
            mutableData.zero()
        }

        let keyAgreementKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        return SecureBytes(data: keyAgreementKey.publicKey.rawRepresentation)
    }

    // MARK: - Key Agreement

    /// Perform X25519 key agreement
    /// - Parameters:
    ///   - privateKey: Our 32-byte private key
    ///   - peerPublicKey: Their 32-byte public key
    /// - Returns: 32-byte shared secret
    public static func keyAgreement(
        privateKey: SecureBytes,
        peerPublicKey: Data
    ) throws -> SecureBytes {
        guard privateKey.count == privateKeySize else {
            throw CryptoError.invalidKeySize(expected: privateKeySize, actual: privateKey.count)
        }

        guard peerPublicKey.count == publicKeySize else {
            throw CryptoError.invalidKeySize(expected: publicKeySize, actual: peerPublicKey.count)
        }

        let privateKeyData = privateKey.toData()
        defer {
            var mutableData = privateKeyData
            mutableData.zero()
        }

        let ourPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let theirPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)

        let sharedSecret = try ourPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)

        // Extract raw bytes from SharedSecret
        return sharedSecret.withUnsafeBytes { buffer in
            SecureBytes(bytes: Array(buffer))
        }
    }

    // MARK: - OpenPGP ECDH (RFC 9580 Section 5.1.6)

    /// OpenPGP ECDH encryption (sender side)
    /// Generates ephemeral key pair, derives shared secret, and derives KEK
    /// - Parameters:
    ///   - recipientPublicKey: Recipient's X25519 public key
    ///   - recipientKeyFingerprint: Recipient key fingerprint for KDF
    /// - Returns: Tuple of (ephemeralPublicKey, wrappedSessionKey derivation material)
    public static func encryptSessionKey(
        sessionKey: SecureBytes,
        recipientPublicKey: Data,
        recipientKeyFingerprint: Data
    ) throws -> (ephemeralPublicKey: Data, wrappedKey: Data) {
        // Generate ephemeral key pair
        let (ephemeralPrivate, ephemeralPublic) = try generateKeyPair()
        defer { ephemeralPrivate.zeroAndDeallocate() }

        // Perform key agreement
        let sharedSecret = try keyAgreement(
            privateKey: ephemeralPrivate,
            peerPublicKey: recipientPublicKey
        )
        defer { sharedSecret.zeroAndDeallocate() }

        // Derive Key Encryption Key using HKDF
        let kek = try deriveKEK(
            sharedSecret: sharedSecret,
            ephemeralPublicKey: ephemeralPublic.toData(),
            recipientPublicKey: recipientPublicKey,
            recipientFingerprint: recipientKeyFingerprint
        )
        defer { kek.zeroAndDeallocate() }

        // Wrap session key using AES Key Wrap (RFC 3394)
        let wrappedKey = try AESKeyWrap.wrap(key: sessionKey, withKEK: kek)

        return (ephemeralPublic.toData(), wrappedKey)
    }

    /// OpenPGP ECDH decryption (recipient side)
    /// Recovers session key from ephemeral public key and wrapped key
    /// - Parameters:
    ///   - wrappedKey: Wrapped session key
    ///   - ephemeralPublicKey: Sender's ephemeral public key
    ///   - recipientPrivateKey: Our private key
    ///   - recipientPublicKey: Our public key
    ///   - recipientFingerprint: Our key fingerprint
    /// - Returns: Unwrapped session key
    public static func decryptSessionKey(
        wrappedKey: Data,
        ephemeralPublicKey: Data,
        recipientPrivateKey: SecureBytes,
        recipientPublicKey: Data,
        recipientFingerprint: Data
    ) throws -> SecureBytes {
        // Perform key agreement with ephemeral public key
        let sharedSecret = try keyAgreement(
            privateKey: recipientPrivateKey,
            peerPublicKey: ephemeralPublicKey
        )
        defer { sharedSecret.zeroAndDeallocate() }

        // Derive Key Encryption Key using same parameters
        let kek = try deriveKEK(
            sharedSecret: sharedSecret,
            ephemeralPublicKey: ephemeralPublicKey,
            recipientPublicKey: recipientPublicKey,
            recipientFingerprint: recipientFingerprint
        )
        defer { kek.zeroAndDeallocate() }

        // Unwrap session key
        return try AESKeyWrap.unwrap(wrappedKey: wrappedKey, withKEK: kek)
    }

    // MARK: - Key Derivation

    /// Derive Key Encryption Key per OpenPGP X25519 (RFC 9580)
    /// Uses HKDF-SHA256 with specific info construction
    private static func deriveKEK(
        sharedSecret: SecureBytes,
        ephemeralPublicKey: Data,
        recipientPublicKey: Data,
        recipientFingerprint: Data
    ) throws -> SecureBytes {
        // Construct HKDF info per RFC 9580 Section 5.1.6
        // info = ephemeral_public || recipient_public || fingerprint
        var info = Data()
        info.append(ephemeralPublicKey)
        info.append(recipientPublicKey)
        info.append(recipientFingerprint)

        // Derive 32-byte KEK using HKDF-SHA256
        return try HKDFOperations.deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: nil,  // No salt per RFC 9580
            info: info,
            outputLength: 32
        )
    }
}

// MARK: - AES Key Wrap (RFC 3394)

/// AES Key Wrap implementation for OpenPGP session key wrapping
public enum AESKeyWrap {

    /// Default IV per RFC 3394
    private static let defaultIV: [UInt8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]

    /// Wrap a key using AES Key Wrap (RFC 3394)
    /// - Parameters:
    ///   - key: Key to wrap (must be multiple of 8 bytes)
    ///   - kek: Key Encryption Key (16, 24, or 32 bytes)
    /// - Returns: Wrapped key (8 bytes longer than input)
    public static func wrap(key: SecureBytes, withKEK kek: SecureBytes) throws -> Data {
        let keyData = key.toData()
        defer {
            var mutableData = keyData
            mutableData.zero()
        }

        let kekData = kek.toData()
        defer {
            var mutableKek = kekData
            mutableKek.zero()
        }

        guard keyData.count >= 16 && keyData.count % 8 == 0 else {
            throw CryptoError.invalidKeySize(expected: 16, actual: keyData.count)
        }

        let n = keyData.count / 8  // Number of 64-bit blocks

        // Initialize
        var a = Data(defaultIV)
        var r = [[UInt8]](repeating: [], count: n)

        // Split plaintext into 64-bit blocks
        for i in 0..<n {
            let start = i * 8
            let end = start + 8
            r[i] = Array(keyData[start..<end])
        }

        // Create AES cipher
        let key = SymmetricKey(data: kekData)

        // Wrap (6 * n iterations)
        for j in 0..<6 {
            for i in 0..<n {
                // B = AES(K, A | R[i])
                var block = Data(a)
                block.append(contentsOf: r[i])

                let encrypted = try AES256Operations.encryptBlock(block: block, key: key)

                // A = MSB(64, B) ^ t where t = (n * j) + (i + 1)
                let t = UInt64(n * j + i + 1)
                a = Data(encrypted.prefix(8))
                a.xor(with: t)

                // R[i] = LSB(64, B)
                r[i] = Array(encrypted.suffix(8))
            }
        }

        // Output: A || R[1] || R[2] || ... || R[n]
        var result = a
        for i in 0..<n {
            result.append(contentsOf: r[i])
        }

        return result
    }

    /// Unwrap a key using AES Key Wrap (RFC 3394)
    /// - Parameters:
    ///   - wrappedKey: Wrapped key data
    ///   - kek: Key Encryption Key
    /// - Returns: Unwrapped key
    public static func unwrap(wrappedKey: Data, withKEK kek: SecureBytes) throws -> SecureBytes {
        let kekData = kek.toData()
        defer {
            var mutableKek = kekData
            mutableKek.zero()
        }

        guard wrappedKey.count >= 24 && (wrappedKey.count - 8) % 8 == 0 else {
            throw CryptoError.invalidCiphertext
        }

        let n = (wrappedKey.count / 8) - 1  // Number of 64-bit blocks

        // Initialize
        var a = Data(wrappedKey.prefix(8))
        var r = [[UInt8]](repeating: [], count: n)

        // Split ciphertext into 64-bit blocks (skip first 8 bytes which is A)
        for i in 0..<n {
            let start = (i + 1) * 8
            let end = start + 8
            r[i] = Array(wrappedKey[start..<end])
        }

        // Create AES cipher
        let key = SymmetricKey(data: kekData)

        // Unwrap (6 * n iterations in reverse)
        for j in (0..<6).reversed() {
            for i in (0..<n).reversed() {
                // A ^ t
                let t = UInt64(n * j + i + 1)
                a.xor(with: t)

                // B = AES^-1(K, (A ^ t) | R[i])
                var block = a
                block.append(contentsOf: r[i])

                let decrypted = try AES256Operations.decryptBlock(block: block, key: key)

                // A = MSB(64, B)
                a = Data(decrypted.prefix(8))

                // R[i] = LSB(64, B)
                r[i] = Array(decrypted.suffix(8))
            }
        }

        // Verify IV
        guard Array(a) == defaultIV else {
            throw CryptoError.integrityCheckFailed
        }

        // Output: R[1] || R[2] || ... || R[n]
        var result = [UInt8]()
        for i in 0..<n {
            result.append(contentsOf: r[i])
        }

        return SecureBytes(bytes: result)
    }
}

// MARK: - Data Extension for XOR

private extension Data {
    mutating func xor(with value: UInt64) {
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { valueBytes in
            for i in 0..<8 {
                self[i] ^= valueBytes[i]
            }
        }
    }
}
