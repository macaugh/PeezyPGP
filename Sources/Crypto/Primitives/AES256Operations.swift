// AES256Operations.swift
// PeezyPGP - Privacy-First OpenPGP
//
// AES-256 symmetric encryption operations
// Supports GCM mode (preferred) and OCB mode for OpenPGP

import Foundation
import CryptoKit

/// AES-256 symmetric encryption operations
public enum AES256Operations {

    // MARK: - Constants

    /// AES-256 key size in bytes
    public static let keySize = 32

    /// GCM nonce size in bytes (96 bits per NIST recommendation)
    public static let gcmNonceSize = 12

    /// GCM authentication tag size in bytes
    public static let gcmTagSize = 16

    /// AES block size in bytes
    public static let blockSize = 16

    // MARK: - GCM Mode (AEAD)

    /// Encrypt data using AES-256-GCM
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - key: 32-byte AES-256 key
    ///   - additionalData: Optional authenticated additional data (AAD)
    /// - Returns: nonce || ciphertext || tag
    public static func encryptGCM(
        plaintext: Data,
        key: SecureBytes,
        additionalData: Data = Data()
    ) throws -> Data {
        guard key.count == keySize else {
            throw CryptoError.invalidKeySize(expected: keySize, actual: key.count)
        }

        let keyData = key.toData()
        defer {
            var mutableKey = keyData
            mutableKey.zero()
        }

        let symmetricKey = SymmetricKey(data: keyData)

        // Generate random nonce
        let nonce = AES.GCM.Nonce()

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: symmetricKey,
            nonce: nonce,
            authenticating: additionalData
        )

        // Return combined representation: nonce || ciphertext || tag
        guard let combined = sealedBox.combined else {
            throw CryptoError.encryptionFailed(underlying: NSError(domain: "AES", code: -1))
        }

        return combined
    }

    /// Encrypt data using AES-256-GCM with explicit nonce
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - key: 32-byte AES-256 key
    ///   - nonce: 12-byte nonce (MUST be unique per key)
    ///   - additionalData: Optional authenticated additional data (AAD)
    /// - Returns: ciphertext || tag (nonce NOT included)
    public static func encryptGCM(
        plaintext: Data,
        key: SecureBytes,
        nonce: Data,
        additionalData: Data = Data()
    ) throws -> Data {
        guard key.count == keySize else {
            throw CryptoError.invalidKeySize(expected: keySize, actual: key.count)
        }

        guard nonce.count == gcmNonceSize else {
            throw CryptoError.invalidNonce
        }

        let keyData = key.toData()
        defer {
            var mutableKey = keyData
            mutableKey.zero()
        }

        let symmetricKey = SymmetricKey(data: keyData)
        let gcmNonce = try AES.GCM.Nonce(data: nonce)

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: symmetricKey,
            nonce: gcmNonce,
            authenticating: additionalData
        )

        // Return ciphertext + tag (without nonce)
        return sealedBox.ciphertext + sealedBox.tag
    }

    /// Decrypt AES-256-GCM data
    /// - Parameters:
    ///   - ciphertext: nonce || ciphertext || tag
    ///   - key: 32-byte AES-256 key
    ///   - additionalData: Optional authenticated additional data (AAD)
    /// - Returns: Decrypted plaintext
    public static func decryptGCM(
        ciphertext: Data,
        key: SecureBytes,
        additionalData: Data = Data()
    ) throws -> Data {
        guard key.count == keySize else {
            throw CryptoError.invalidKeySize(expected: keySize, actual: key.count)
        }

        // Minimum size: nonce (12) + tag (16) = 28 bytes
        guard ciphertext.count >= gcmNonceSize + gcmTagSize else {
            throw CryptoError.invalidCiphertext
        }

        let keyData = key.toData()
        defer {
            var mutableKey = keyData
            mutableKey.zero()
        }

        let symmetricKey = SymmetricKey(data: keyData)

        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)

        let plaintext = try AES.GCM.open(
            sealedBox,
            using: symmetricKey,
            authenticating: additionalData
        )

        return plaintext
    }

    /// Decrypt AES-256-GCM data with explicit nonce
    /// - Parameters:
    ///   - ciphertext: ciphertext || tag (nonce separate)
    ///   - key: 32-byte AES-256 key
    ///   - nonce: 12-byte nonce
    ///   - additionalData: Optional authenticated additional data (AAD)
    /// - Returns: Decrypted plaintext
    public static func decryptGCM(
        ciphertext: Data,
        key: SecureBytes,
        nonce: Data,
        additionalData: Data = Data()
    ) throws -> Data {
        guard key.count == keySize else {
            throw CryptoError.invalidKeySize(expected: keySize, actual: key.count)
        }

        guard nonce.count == gcmNonceSize else {
            throw CryptoError.invalidNonce
        }

        guard ciphertext.count >= gcmTagSize else {
            throw CryptoError.invalidCiphertext
        }

        let keyData = key.toData()
        defer {
            var mutableKey = keyData
            mutableKey.zero()
        }

        let symmetricKey = SymmetricKey(data: keyData)
        let gcmNonce = try AES.GCM.Nonce(data: nonce)

        // Split ciphertext and tag
        let encryptedData = ciphertext.prefix(ciphertext.count - gcmTagSize)
        let tag = ciphertext.suffix(gcmTagSize)

        let sealedBox = try AES.GCM.SealedBox(
            nonce: gcmNonce,
            ciphertext: encryptedData,
            tag: tag
        )

        return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: additionalData)
    }

    // MARK: - ECB Mode (for Key Wrap only - NOT for general encryption)

    /// Encrypt a single 16-byte block using AES-256-ECB
    /// ONLY used for AES Key Wrap (RFC 3394) - never for general data
    internal static func encryptBlock(block: Data, key: SymmetricKey) throws -> Data {
        guard block.count == blockSize else {
            throw CryptoError.invalidCiphertext
        }

        // Use AES-GCM with zero nonce and extract just the ciphertext
        // This is a workaround since CryptoKit doesn't expose raw AES
        // For production, consider using CommonCrypto or a dedicated AES implementation

        // We'll implement a proper ECB block encrypt using a different approach
        // Using the lower-level AES from Security framework

        var result = Data(count: blockSize)
        var resultCount = blockSize

        let status = block.withUnsafeBytes { blockBytes in
            key.withUnsafeBytes { keyBytes in
                result.withUnsafeMutableBytes { resultBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress!,
                        keyBytes.count,
                        nil,  // No IV for ECB
                        blockBytes.baseAddress!,
                        blockSize,
                        resultBytes.baseAddress!,
                        blockSize,
                        &resultCount
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed(underlying: NSError(domain: "CommonCrypto", code: Int(status)))
        }

        return result
    }

    /// Decrypt a single 16-byte block using AES-256-ECB
    /// ONLY used for AES Key Wrap (RFC 3394) - never for general data
    internal static func decryptBlock(block: Data, key: SymmetricKey) throws -> Data {
        guard block.count == blockSize else {
            throw CryptoError.invalidCiphertext
        }

        var result = Data(count: blockSize)
        var resultCount = blockSize

        let status = block.withUnsafeBytes { blockBytes in
            key.withUnsafeBytes { keyBytes in
                result.withUnsafeMutableBytes { resultBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes.baseAddress!,
                        keyBytes.count,
                        nil,
                        blockBytes.baseAddress!,
                        blockSize,
                        resultBytes.baseAddress!,
                        blockSize,
                        &resultCount
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.decryptionFailed(underlying: NSError(domain: "CommonCrypto", code: Int(status)))
        }

        return result
    }

    // MARK: - Session Key Generation

    /// Generate a random AES-256 session key
    /// - Returns: 32-byte random key as SecureBytes
    public static func generateSessionKey() -> SecureBytes {
        return SecureBytes(randomBytes: keySize)
    }
}

// MARK: - CommonCrypto Bridge

import CommonCrypto

private let kCCSuccess: Int32 = 0
private let kCCEncrypt: Int = 0
private let kCCDecrypt: Int = 1
private let kCCAlgorithmAES: Int = 0
private let kCCOptionECBMode: Int = 2

private func CCCrypt(
    _ op: CCOperation,
    _ alg: CCAlgorithm,
    _ options: CCOptions,
    _ key: UnsafeRawPointer,
    _ keyLength: Int,
    _ iv: UnsafeRawPointer?,
    _ dataIn: UnsafeRawPointer,
    _ dataInLength: Int,
    _ dataOut: UnsafeMutableRawPointer,
    _ dataOutAvailable: Int,
    _ dataOutMoved: inout Int
) -> Int32 {
    return CommonCrypto.CCCrypt(
        op, alg, options,
        key, keyLength,
        iv,
        dataIn, dataInLength,
        dataOut, dataOutAvailable,
        &dataOutMoved
    )
}
