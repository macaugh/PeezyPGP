// AES256Tests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class AES256Tests: XCTestCase {

    // MARK: - GCM Encrypt/Decrypt Round-Trip (Auto Nonce)

    func testEncryptDecryptRoundTrip() throws {
        let key = AES256Operations.generateSessionKey()
        let plaintext = "Hello, PeezyPGP!".data(using: .utf8)!

        let ciphertext = try AES256Operations.encryptGCM(plaintext: plaintext, key: key)
        let decrypted = try AES256Operations.decryptGCM(ciphertext: ciphertext, key: key)

        XCTAssertEqual(decrypted, plaintext)

        key.zeroAndDeallocate()
    }

    func testEncryptDecryptEmptyData() throws {
        let key = AES256Operations.generateSessionKey()
        let plaintext = Data()

        let ciphertext = try AES256Operations.encryptGCM(plaintext: plaintext, key: key)
        let decrypted = try AES256Operations.decryptGCM(ciphertext: ciphertext, key: key)

        XCTAssertEqual(decrypted, plaintext)

        key.zeroAndDeallocate()
    }

    func testEncryptDecryptLargeData() throws {
        let key = AES256Operations.generateSessionKey()
        let plaintext = Data(repeating: 0xAB, count: 1_000_000) // 1 MB

        let ciphertext = try AES256Operations.encryptGCM(plaintext: plaintext, key: key)
        let decrypted = try AES256Operations.decryptGCM(ciphertext: ciphertext, key: key)

        XCTAssertEqual(decrypted, plaintext)

        key.zeroAndDeallocate()
    }

    // MARK: - GCM Encrypt/Decrypt with Explicit Nonce

    func testEncryptDecryptExplicitNonce() throws {
        let key = AES256Operations.generateSessionKey()
        let nonce = Data(SecureBytes(randomBytes: AES256Operations.gcmNonceSize).toBytes())
        let plaintext = "Explicit nonce test".data(using: .utf8)!

        let ciphertext = try AES256Operations.encryptGCM(
            plaintext: plaintext, key: key, nonce: nonce
        )
        let decrypted = try AES256Operations.decryptGCM(
            ciphertext: ciphertext, key: key, nonce: nonce
        )

        XCTAssertEqual(decrypted, plaintext)

        key.zeroAndDeallocate()
    }

    // MARK: - Wrong Key Rejection

    func testDecryptWithWrongKey() throws {
        let key1 = AES256Operations.generateSessionKey()
        let key2 = AES256Operations.generateSessionKey()
        let plaintext = "Secret message".data(using: .utf8)!

        let ciphertext = try AES256Operations.encryptGCM(plaintext: plaintext, key: key1)

        XCTAssertThrowsError(try AES256Operations.decryptGCM(ciphertext: ciphertext, key: key2))

        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }

    // MARK: - Tampered Ciphertext

    func testTamperedCiphertext() throws {
        let key = AES256Operations.generateSessionKey()
        let plaintext = "Tamper test".data(using: .utf8)!

        var ciphertext = try AES256Operations.encryptGCM(plaintext: plaintext, key: key)

        // Flip a byte in the middle of the ciphertext body
        let midpoint = AES256Operations.gcmNonceSize + (ciphertext.count - AES256Operations.gcmNonceSize - AES256Operations.gcmTagSize) / 2
        ciphertext[midpoint] ^= 0xFF

        XCTAssertThrowsError(try AES256Operations.decryptGCM(ciphertext: ciphertext, key: key))

        key.zeroAndDeallocate()
    }

    // MARK: - Truncated Ciphertext

    func testTruncatedCiphertext() throws {
        let key = AES256Operations.generateSessionKey()

        // Too short to contain nonce + tag
        let truncated = Data(repeating: 0, count: 10)

        XCTAssertThrowsError(try AES256Operations.decryptGCM(ciphertext: truncated, key: key)) { error in
            guard case CryptoError.invalidCiphertext = error else {
                XCTFail("Expected invalidCiphertext error, got \(error)")
                return
            }
        }

        key.zeroAndDeallocate()
    }

    // MARK: - AAD Mismatch

    func testAADMismatch() throws {
        let key = AES256Operations.generateSessionKey()
        let plaintext = "AAD test".data(using: .utf8)!
        let aad1 = "context-1".data(using: .utf8)!
        let aad2 = "context-2".data(using: .utf8)!

        let ciphertext = try AES256Operations.encryptGCM(
            plaintext: plaintext, key: key, additionalData: aad1
        )

        // Decrypt with different AAD should fail
        XCTAssertThrowsError(try AES256Operations.decryptGCM(
            ciphertext: ciphertext, key: key, additionalData: aad2
        ))

        // Decrypt with correct AAD should succeed
        let decrypted = try AES256Operations.decryptGCM(
            ciphertext: ciphertext, key: key, additionalData: aad1
        )
        XCTAssertEqual(decrypted, plaintext)

        key.zeroAndDeallocate()
    }

    // MARK: - Invalid Key Size

    func testInvalidKeySize() {
        let invalidKey = SecureBytes(randomBytes: 16) // AES-128, not AES-256
        let plaintext = "test".data(using: .utf8)!

        XCTAssertThrowsError(try AES256Operations.encryptGCM(plaintext: plaintext, key: invalidKey)) { error in
            guard case CryptoError.invalidKeySize = error else {
                XCTFail("Expected invalidKeySize error, got \(error)")
                return
            }
        }

        invalidKey.zeroAndDeallocate()
    }

    // MARK: - Invalid Nonce Size

    func testInvalidNonceSize() {
        let key = AES256Operations.generateSessionKey()
        let plaintext = "test".data(using: .utf8)!
        let invalidNonce = Data(repeating: 0, count: 8) // Wrong size

        XCTAssertThrowsError(try AES256Operations.encryptGCM(
            plaintext: plaintext, key: key, nonce: invalidNonce
        )) { error in
            guard case CryptoError.invalidNonce = error else {
                XCTFail("Expected invalidNonce error, got \(error)")
                return
            }
        }

        key.zeroAndDeallocate()
    }

    // MARK: - Session Key Generation

    func testSessionKeyGeneration() {
        let key1 = AES256Operations.generateSessionKey()
        let key2 = AES256Operations.generateSessionKey()

        XCTAssertEqual(key1.count, AES256Operations.keySize)
        XCTAssertEqual(key2.count, AES256Operations.keySize)
        XCTAssertFalse(key1.constantTimeEquals(key2))

        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }
}
