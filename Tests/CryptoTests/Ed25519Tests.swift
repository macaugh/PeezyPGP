// Ed25519Tests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class Ed25519Tests: XCTestCase {

    // MARK: - Key Generation

    func testKeyGeneration() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()

        XCTAssertEqual(privateKey.count, Ed25519Operations.privateKeySize)
        XCTAssertEqual(publicKey.count, Ed25519Operations.publicKeySize)

        // Keys should be different
        XCTAssertFalse(privateKey.constantTimeEquals(publicKey))

        // Cleanup
        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    func testKeyGenerationDeterminism() throws {
        // Two key generations should produce different keys
        let (priv1, pub1) = try Ed25519Operations.generateKeyPair()
        let (priv2, pub2) = try Ed25519Operations.generateKeyPair()

        XCTAssertFalse(priv1.constantTimeEquals(priv2))
        XCTAssertFalse(pub1.constantTimeEquals(pub2))

        priv1.zeroAndDeallocate()
        pub1.zeroAndDeallocate()
        priv2.zeroAndDeallocate()
        pub2.zeroAndDeallocate()
    }

    // MARK: - Public Key Derivation

    func testPublicKeyDerivation() throws {
        let (privateKey, expectedPublicKey) = try Ed25519Operations.generateKeyPair()
        let derivedPublicKey = try Ed25519Operations.derivePublicKey(from: privateKey)

        XCTAssertTrue(expectedPublicKey.constantTimeEquals(derivedPublicKey))

        privateKey.zeroAndDeallocate()
        expectedPublicKey.zeroAndDeallocate()
        derivedPublicKey.zeroAndDeallocate()
    }

    func testPublicKeyDerivationInvalidSize() {
        let invalidKey = SecureBytes(zeroedCount: 16) // Wrong size

        XCTAssertThrowsError(try Ed25519Operations.derivePublicKey(from: invalidKey)) { error in
            guard case CryptoError.invalidKeySize = error else {
                XCTFail("Expected invalidKeySize error")
                return
            }
        }

        invalidKey.zeroAndDeallocate()
    }

    // MARK: - Signing

    func testSignAndVerify() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = "Hello, PeezyPGP!".data(using: .utf8)!

        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey)

        XCTAssertEqual(signature.count, Ed25519Operations.signatureSize)

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: message,
            publicKey: publicKey.toData()
        )
        XCTAssertTrue(isValid)

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    func testSignatureInvalidForModifiedMessage() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = "Hello, PeezyPGP!".data(using: .utf8)!
        let modifiedMessage = "Hello, Modified!".data(using: .utf8)!

        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey)

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: modifiedMessage,
            publicKey: publicKey.toData()
        )
        XCTAssertFalse(isValid)

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    func testSignatureInvalidForWrongKey() throws {
        let (privateKey1, _) = try Ed25519Operations.generateKeyPair()
        let (_, publicKey2) = try Ed25519Operations.generateKeyPair()
        let message = "Hello, PeezyPGP!".data(using: .utf8)!

        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey1)

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: message,
            publicKey: publicKey2.toData()
        )
        XCTAssertFalse(isValid)

        privateKey1.zeroAndDeallocate()
        publicKey2.zeroAndDeallocate()
    }

    func testSignEmptyMessage() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = Data()

        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey)

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: message,
            publicKey: publicKey.toData()
        )
        XCTAssertTrue(isValid)

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    func testSignLargeMessage() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = Data(repeating: 0xAB, count: 1_000_000) // 1MB

        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey)

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: message,
            publicKey: publicKey.toData()
        )
        XCTAssertTrue(isValid)

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    // MARK: - Edge Cases

    func testInvalidSignatureLength() throws {
        let (_, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = "Test".data(using: .utf8)!
        let invalidSignature = Data(repeating: 0, count: 32) // Wrong size

        let isValid = Ed25519Operations.verify(
            signature: invalidSignature,
            message: message,
            publicKey: publicKey.toData()
        )
        XCTAssertFalse(isValid)

        publicKey.zeroAndDeallocate()
    }

    func testInvalidPublicKeyLength() throws {
        let message = "Test".data(using: .utf8)!
        let signature = Data(repeating: 0, count: 64)
        let invalidPublicKey = Data(repeating: 0, count: 16) // Wrong size

        let isValid = Ed25519Operations.verify(
            signature: signature,
            message: message,
            publicKey: invalidPublicKey
        )
        XCTAssertFalse(isValid)
    }

    // MARK: - Performance

    func testKeyGenerationPerformance() throws {
        measure {
            for _ in 0..<100 {
                do {
                    let (priv, pub) = try Ed25519Operations.generateKeyPair()
                    priv.zeroAndDeallocate()
                    pub.zeroAndDeallocate()
                } catch {
                    XCTFail("Key generation failed: \(error)")
                }
            }
        }
    }

    func testSigningPerformance() throws {
        let (privateKey, _) = try Ed25519Operations.generateKeyPair()
        let message = Data(repeating: 0xAB, count: 1024)

        measure {
            for _ in 0..<1000 {
                _ = try? Ed25519Operations.sign(message: message, privateKey: privateKey)
            }
        }

        privateKey.zeroAndDeallocate()
    }

    func testVerificationPerformance() throws {
        let (privateKey, publicKey) = try Ed25519Operations.generateKeyPair()
        let message = Data(repeating: 0xAB, count: 1024)
        let signature = try Ed25519Operations.sign(message: message, privateKey: privateKey)
        let pubKeyData = publicKey.toData()

        measure {
            for _ in 0..<1000 {
                _ = Ed25519Operations.verify(
                    signature: signature,
                    message: message,
                    publicKey: pubKeyData
                )
            }
        }

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }
}
