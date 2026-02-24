// X25519Tests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class X25519Tests: XCTestCase {

    // MARK: - Key Generation

    func testKeyGeneration() throws {
        let (privateKey, publicKey) = try X25519Operations.generateKeyPair()

        XCTAssertEqual(privateKey.count, X25519Operations.privateKeySize)
        XCTAssertEqual(publicKey.count, X25519Operations.publicKeySize)

        XCTAssertFalse(privateKey.constantTimeEquals(publicKey))

        privateKey.zeroAndDeallocate()
        publicKey.zeroAndDeallocate()
    }

    func testKeyGenerationUniqueness() throws {
        let (priv1, pub1) = try X25519Operations.generateKeyPair()
        let (priv2, pub2) = try X25519Operations.generateKeyPair()

        XCTAssertFalse(priv1.constantTimeEquals(priv2))
        XCTAssertFalse(pub1.constantTimeEquals(pub2))

        priv1.zeroAndDeallocate()
        pub1.zeroAndDeallocate()
        priv2.zeroAndDeallocate()
        pub2.zeroAndDeallocate()
    }

    // MARK: - Public Key Derivation

    func testPublicKeyDerivation() throws {
        let (privateKey, expectedPublicKey) = try X25519Operations.generateKeyPair()
        let derivedPublicKey = try X25519Operations.derivePublicKey(from: privateKey)

        XCTAssertTrue(expectedPublicKey.constantTimeEquals(derivedPublicKey))

        privateKey.zeroAndDeallocate()
        expectedPublicKey.zeroAndDeallocate()
        derivedPublicKey.zeroAndDeallocate()
    }

    func testPublicKeyDerivationInvalidSize() {
        let invalidKey = SecureBytes(zeroedCount: 16)

        XCTAssertThrowsError(try X25519Operations.derivePublicKey(from: invalidKey)) { error in
            guard case CryptoError.invalidKeySize = error else {
                XCTFail("Expected invalidKeySize error, got \(error)")
                return
            }
        }

        invalidKey.zeroAndDeallocate()
    }

    // MARK: - Key Agreement

    func testKeyAgreementSymmetry() throws {
        let (alicePriv, alicePub) = try X25519Operations.generateKeyPair()
        let (bobPriv, bobPub) = try X25519Operations.generateKeyPair()

        let aliceShared = try X25519Operations.keyAgreement(
            privateKey: alicePriv,
            peerPublicKey: bobPub.toData()
        )
        let bobShared = try X25519Operations.keyAgreement(
            privateKey: bobPriv,
            peerPublicKey: alicePub.toData()
        )

        XCTAssertTrue(aliceShared.constantTimeEquals(bobShared),
                       "Alice and Bob should derive the same shared secret")
        XCTAssertEqual(aliceShared.count, X25519Operations.sharedSecretSize)

        alicePriv.zeroAndDeallocate()
        alicePub.zeroAndDeallocate()
        bobPriv.zeroAndDeallocate()
        bobPub.zeroAndDeallocate()
        aliceShared.zeroAndDeallocate()
        bobShared.zeroAndDeallocate()
    }

    func testKeyAgreementInvalidPrivateKeySize() {
        let invalidKey = SecureBytes(zeroedCount: 16)
        let peerPub = Data(repeating: 0x42, count: 32)

        XCTAssertThrowsError(try X25519Operations.keyAgreement(
            privateKey: invalidKey,
            peerPublicKey: peerPub
        )) { error in
            guard case CryptoError.invalidKeySize = error else {
                XCTFail("Expected invalidKeySize error, got \(error)")
                return
            }
        }

        invalidKey.zeroAndDeallocate()
    }

    func testKeyAgreementInvalidPublicKeySize() throws {
        let (priv, _) = try X25519Operations.generateKeyPair()
        let invalidPub = Data(repeating: 0x42, count: 16)

        XCTAssertThrowsError(try X25519Operations.keyAgreement(
            privateKey: priv,
            peerPublicKey: invalidPub
        )) { error in
            guard case CryptoError.invalidKeySize = error else {
                XCTFail("Expected invalidKeySize error, got \(error)")
                return
            }
        }

        priv.zeroAndDeallocate()
    }

    // MARK: - Session Key Encrypt/Decrypt Round-Trip

    func testSessionKeyRoundTrip() throws {
        let (recipientPriv, recipientPub) = try X25519Operations.generateKeyPair()
        let sessionKey = AES256Operations.generateSessionKey()
        let fingerprint = Data(repeating: 0xAA, count: 20)

        let (ephemeralPub, wrappedKey) = try X25519Operations.encryptSessionKey(
            sessionKey: sessionKey,
            recipientPublicKey: recipientPub.toData(),
            recipientKeyFingerprint: fingerprint
        )

        let recoveredKey = try X25519Operations.decryptSessionKey(
            wrappedKey: wrappedKey,
            ephemeralPublicKey: ephemeralPub,
            recipientPrivateKey: recipientPriv,
            recipientPublicKey: recipientPub.toData(),
            recipientFingerprint: fingerprint
        )

        XCTAssertTrue(sessionKey.constantTimeEquals(recoveredKey),
                       "Decrypted session key should match original")

        recipientPriv.zeroAndDeallocate()
        recipientPub.zeroAndDeallocate()
        sessionKey.zeroAndDeallocate()
        recoveredKey.zeroAndDeallocate()
    }

    func testSessionKeyWrongRecipientFails() throws {
        let (_, recipientPub) = try X25519Operations.generateKeyPair()
        let (wrongPriv, wrongPub) = try X25519Operations.generateKeyPair()
        let sessionKey = AES256Operations.generateSessionKey()
        let fingerprint = Data(repeating: 0xAA, count: 20)

        let (ephemeralPub, wrappedKey) = try X25519Operations.encryptSessionKey(
            sessionKey: sessionKey,
            recipientPublicKey: recipientPub.toData(),
            recipientKeyFingerprint: fingerprint
        )

        // Attempt to decrypt with the wrong recipient's private key
        XCTAssertThrowsError(try X25519Operations.decryptSessionKey(
            wrappedKey: wrappedKey,
            ephemeralPublicKey: ephemeralPub,
            recipientPrivateKey: wrongPriv,
            recipientPublicKey: wrongPub.toData(),
            recipientFingerprint: fingerprint
        ))

        recipientPub.zeroAndDeallocate()
        wrongPriv.zeroAndDeallocate()
        wrongPub.zeroAndDeallocate()
        sessionKey.zeroAndDeallocate()
    }
}
