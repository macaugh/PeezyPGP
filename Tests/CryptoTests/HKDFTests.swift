// HKDFTests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class HKDFTests: XCTestCase {

    // MARK: - Determinism

    func testDeriveKeyDeterministic() throws {
        let ikm = SecureBytes(randomBytes: 32)
        let salt = Data(repeating: 0x01, count: 32)
        let info = "test-info".data(using: .utf8)!

        let key1 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: salt, info: info, outputLength: 32
        )
        let key2 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: salt, info: info, outputLength: 32
        )

        XCTAssertTrue(key1.constantTimeEquals(key2),
                       "Same inputs should produce same output")

        ikm.zeroAndDeallocate()
        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }

    // MARK: - Different Info Produces Different Keys

    func testDifferentInfoProducesDifferentKeys() throws {
        let ikm = SecureBytes(randomBytes: 32)
        let salt = Data(repeating: 0x01, count: 32)

        let key1 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: salt,
            info: "context-A".data(using: .utf8)!, outputLength: 32
        )
        let key2 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: salt,
            info: "context-B".data(using: .utf8)!, outputLength: 32
        )

        XCTAssertFalse(key1.constantTimeEquals(key2),
                        "Different info should produce different keys")

        ikm.zeroAndDeallocate()
        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }

    // MARK: - Different Salt Produces Different Keys

    func testDifferentSaltProducesDifferentKeys() throws {
        let ikm = SecureBytes(randomBytes: 32)
        let info = "test".data(using: .utf8)!

        let key1 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm,
            salt: Data(repeating: 0x01, count: 32),
            info: info, outputLength: 32
        )
        let key2 = try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm,
            salt: Data(repeating: 0x02, count: 32),
            info: info, outputLength: 32
        )

        XCTAssertFalse(key1.constantTimeEquals(key2),
                        "Different salts should produce different keys")

        ikm.zeroAndDeallocate()
        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }

    // MARK: - Various Output Lengths

    func testVariousOutputLengths() throws {
        let ikm = SecureBytes(randomBytes: 32)
        let info = "length-test".data(using: .utf8)!

        for length in [16, 32, 48, 64, 128] {
            let key = try HKDFOperations.deriveKey(
                inputKeyMaterial: ikm, salt: nil, info: info, outputLength: length
            )
            XCTAssertEqual(key.count, length, "Output should be \(length) bytes")
            key.zeroAndDeallocate()
        }

        ikm.zeroAndDeallocate()
    }

    // MARK: - Invalid Output Lengths

    func testInvalidOutputLengthZero() {
        let ikm = SecureBytes(randomBytes: 32)
        let info = Data()

        XCTAssertThrowsError(try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: nil, info: info, outputLength: 0
        )) { error in
            guard case CryptoError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error, got \(error)")
                return
            }
        }

        ikm.zeroAndDeallocate()
    }

    func testInvalidOutputLengthTooLarge() {
        let ikm = SecureBytes(randomBytes: 32)
        let info = Data()

        // SHA-256 max: 255 * 32 = 8160
        XCTAssertThrowsError(try HKDFOperations.deriveKey(
            inputKeyMaterial: ikm, salt: nil, info: info, outputLength: 8161
        )) { error in
            guard case CryptoError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error, got \(error)")
                return
            }
        }

        ikm.zeroAndDeallocate()
    }

    // MARK: - SHA-512 Variant

    func testDeriveKeySHA512() throws {
        let ikm = SecureBytes(randomBytes: 32)
        let salt = Data(repeating: 0x42, count: 64)
        let info = "sha512-test".data(using: .utf8)!

        let key = try HKDFOperations.deriveKeySHA512(
            inputKeyMaterial: ikm, salt: salt, info: info, outputLength: 64
        )

        XCTAssertEqual(key.count, 64)

        ikm.zeroAndDeallocate()
        key.zeroAndDeallocate()
    }

    func testDeriveKeySHA512InvalidLength() {
        let ikm = SecureBytes(randomBytes: 32)
        let info = Data()

        // SHA-512 max: 255 * 64 = 16320
        XCTAssertThrowsError(try HKDFOperations.deriveKeySHA512(
            inputKeyMaterial: ikm, salt: nil, info: info, outputLength: 16321
        )) { error in
            guard case CryptoError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error, got \(error)")
                return
            }
        }

        ikm.zeroAndDeallocate()
    }

    // MARK: - OpenPGP Message Key Derivation

    func testDeriveOpenPGPMessageKey() throws {
        let sessionKey = SecureBytes(randomBytes: 32)
        let salt = Data(repeating: 0xBB, count: 32)

        let (messageKey, nonce) = try HKDFOperations.deriveOpenPGPMessageKey(
            sessionKey: sessionKey, salt: salt
        )

        XCTAssertEqual(messageKey.count, 32, "Message key should be 32 bytes")
        XCTAssertEqual(nonce.count, 12, "Nonce should be 12 bytes")

        sessionKey.zeroAndDeallocate()
        messageKey.zeroAndDeallocate()
    }

    func testDeriveOpenPGPMessageKeyDeterministic() throws {
        let sessionKey = SecureBytes(randomBytes: 32)
        let salt = Data(repeating: 0xCC, count: 32)

        let (key1, nonce1) = try HKDFOperations.deriveOpenPGPMessageKey(
            sessionKey: sessionKey, salt: salt
        )
        let (key2, nonce2) = try HKDFOperations.deriveOpenPGPMessageKey(
            sessionKey: sessionKey, salt: salt
        )

        XCTAssertTrue(key1.constantTimeEquals(key2))
        XCTAssertEqual(nonce1, nonce2)

        sessionKey.zeroAndDeallocate()
        key1.zeroAndDeallocate()
        key2.zeroAndDeallocate()
    }

    func testDeriveOpenPGPMessageKeyInvalidSalt() {
        let sessionKey = SecureBytes(randomBytes: 32)
        let badSalt = Data(repeating: 0, count: 16) // Not 32 bytes

        XCTAssertThrowsError(try HKDFOperations.deriveOpenPGPMessageKey(
            sessionKey: sessionKey, salt: badSalt
        )) { error in
            guard case CryptoError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error, got \(error)")
                return
            }
        }

        sessionKey.zeroAndDeallocate()
    }

    // MARK: - SHA2 Operations

    func testSHA256KnownVector() {
        // SHA-256 of empty string
        let hash = SHA2Operations.sha256(Data())
        XCTAssertEqual(hash.count, 32)
        // Known value: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = Data([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ])
        XCTAssertEqual(hash, expected)
    }

    func testSHA512KnownVector() {
        // SHA-512 of empty string
        let hash = SHA2Operations.sha512(Data())
        XCTAssertEqual(hash.count, 64)
        // First 4 bytes of SHA-512(""): cf83e135
        XCTAssertEqual(hash[0], 0xcf)
        XCTAssertEqual(hash[1], 0x83)
        XCTAssertEqual(hash[2], 0xe1)
        XCTAssertEqual(hash[3], 0x35)
    }

    func testSHA256WithSecureBytes() {
        let data = "Hello".data(using: .utf8)!
        let secureBytes = SecureBytes(data: data)

        let hashFromData = SHA2Operations.sha256(data)
        let hashFromSecure = SHA2Operations.sha256(secureBytes)

        XCTAssertEqual(hashFromData, hashFromSecure)

        secureBytes.zeroAndDeallocate()
    }

    func testSHA512WithSecureBytes() {
        let data = "Hello".data(using: .utf8)!
        let secureBytes = SecureBytes(data: data)

        let hashFromData = SHA2Operations.sha512(data)
        let hashFromSecure = SHA2Operations.sha512(secureBytes)

        XCTAssertEqual(hashFromData, hashFromSecure)

        secureBytes.zeroAndDeallocate()
    }

    // MARK: - Incremental Hashers

    func testSHA256IncrementalHasher() {
        let part1 = "Hello, ".data(using: .utf8)!
        let part2 = "World!".data(using: .utf8)!
        let combined = "Hello, World!".data(using: .utf8)!

        let hasher = SHA2Operations.SHA256Hasher()
        hasher.update(part1)
        hasher.update(part2)
        let incrementalHash = hasher.finalize()

        let directHash = SHA2Operations.sha256(combined)

        XCTAssertEqual(incrementalHash, directHash)
    }

    func testSHA512IncrementalHasher() {
        let part1 = "Hello, ".data(using: .utf8)!
        let part2 = "World!".data(using: .utf8)!
        let combined = "Hello, World!".data(using: .utf8)!

        let hasher = SHA2Operations.SHA512Hasher()
        hasher.update(part1)
        hasher.update(part2)
        let incrementalHash = hasher.finalize()

        let directHash = SHA2Operations.sha512(combined)

        XCTAssertEqual(incrementalHash, directHash)
    }

    func testSHA256HasherWithBytes() {
        let bytes: [UInt8] = [0x01, 0x02, 0x03]
        let data = Data(bytes)

        let hasher = SHA2Operations.SHA256Hasher()
        hasher.update(bytes)
        let hashFromBytes = hasher.finalize()

        let hashFromData = SHA2Operations.sha256(data)

        XCTAssertEqual(hashFromBytes, hashFromData)
    }
}
