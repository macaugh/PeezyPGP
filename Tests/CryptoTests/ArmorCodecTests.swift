// ArmorCodecTests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class ArmorCodecTests: XCTestCase {

    // MARK: - Round-Trip All Armor Types

    func testRoundTripPublicKey() throws {
        let data = Data(repeating: 0xAB, count: 64)
        let armor = ArmorCodec.encode(data, type: .publicKey)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .publicKey)
    }

    func testRoundTripPrivateKey() throws {
        let data = Data(repeating: 0xCD, count: 64)
        let armor = ArmorCodec.encode(data, type: .privateKey)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .privateKey)
    }

    func testRoundTripMessage() throws {
        let data = Data(repeating: 0xEF, count: 128)
        let armor = ArmorCodec.encode(data, type: .message)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .message)
    }

    func testRoundTripSignature() throws {
        let data = Data(repeating: 0x12, count: 64)
        let armor = ArmorCodec.encode(data, type: .signature)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .signature)
    }

    func testRoundTripSignedMessage() throws {
        let data = Data(repeating: 0x34, count: 96)
        let armor = ArmorCodec.encode(data, type: .signedMessage)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .signedMessage)
    }

    // MARK: - Custom Headers

    func testCustomHeaders() throws {
        let data = Data(repeating: 0x42, count: 32)
        let headers = ["Version": "PeezyPGP 1.0", "Comment": "Test key"]

        let armor = ArmorCodec.encode(data, type: .publicKey, headers: headers)
        let (decoded, _, decodedHeaders) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(decodedHeaders["Version"], "PeezyPGP 1.0")
        XCTAssertEqual(decodedHeaders["Comment"], "Test key")
    }

    // MARK: - CRC-24 Verification

    func testChecksumTampering() throws {
        let data = Data(repeating: 0xAB, count: 64)
        var armor = ArmorCodec.encode(data, type: .publicKey)

        // Find the checksum line (starts with =) and corrupt it
        let lines = armor.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var tampered = [String]()
        for line in lines {
            if line.hasPrefix("=") && line.count == 5 {
                // Replace checksum with a different one
                tampered.append("=AAAA")
            } else {
                tampered.append(line)
            }
        }
        armor = tampered.joined(separator: "\n")

        XCTAssertThrowsError(try ArmorCodec.decode(armor)) { error in
            guard case CryptoError.checksumMismatch = error else {
                XCTFail("Expected checksumMismatch error, got \(error)")
                return
            }
        }
    }

    // MARK: - Body Tampering

    func testBodyTampering() throws {
        let data = Data(repeating: 0xAB, count: 64)
        var armor = ArmorCodec.encode(data, type: .publicKey)

        // Tamper with a base64 character in the body
        var lines = armor.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        // Find first non-header, non-empty, non-checksum, non-boundary line
        for i in 0..<lines.count {
            let line = lines[i]
            if !line.hasPrefix("-----") && !line.hasPrefix("=") && !line.isEmpty
                && !line.contains(":") {
                // Replace first character
                var chars = Array(line)
                chars[0] = (chars[0] == "A") ? "B" : "A"
                lines[i] = String(chars)
                break
            }
        }
        armor = lines.joined(separator: "\n")

        XCTAssertThrowsError(try ArmorCodec.decode(armor)) { error in
            // Should fail on checksum mismatch or invalid base64
            let isCryptoError = error is CryptoError
            XCTAssertTrue(isCryptoError, "Expected CryptoError, got \(error)")
        }
    }

    // MARK: - Missing Header / Footer

    func testMissingHeader() {
        let armor = """
        Some random text without a PGP header
        =AAAA
        -----END PGP PUBLIC KEY BLOCK-----
        """

        XCTAssertThrowsError(try ArmorCodec.decode(armor)) { error in
            guard case CryptoError.armorFormatError = error else {
                XCTFail("Expected armorFormatError, got \(error)")
                return
            }
        }
    }

    func testMissingFooter() {
        let armor = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        AQID
        =t7jb
        """

        XCTAssertThrowsError(try ArmorCodec.decode(armor)) { error in
            guard case CryptoError.armorFormatError = error else {
                XCTFail("Expected armorFormatError, got \(error)")
                return
            }
        }
    }

    // MARK: - Unknown Armor Type

    func testUnknownArmorType() {
        let armor = """
        -----BEGIN PGP UNKNOWN BLOCK-----

        AQID
        =t7jb
        -----END PGP UNKNOWN BLOCK-----
        """

        XCTAssertThrowsError(try ArmorCodec.decode(armor)) { error in
            guard case CryptoError.armorFormatError = error else {
                XCTFail("Expected armorFormatError, got \(error)")
                return
            }
        }
    }

    // MARK: - Empty Data

    func testEmptyDataRoundTrip() throws {
        let data = Data()
        let armor = ArmorCodec.encode(data, type: .message)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .message)
    }

    // MARK: - Large Data

    func testLargeDataRoundTrip() throws {
        let data = Data(repeating: 0xFF, count: 100_000)
        let armor = ArmorCodec.encode(data, type: .message)
        let (decoded, type, _) = try ArmorCodec.decode(armor)

        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .message)
    }

    // MARK: - Line Wrapping

    func testLineWrapping() {
        let data = Data(repeating: 0xAB, count: 128) // Enough to span multiple lines
        let armor = ArmorCodec.encode(data, type: .publicKey)

        let lines = armor.split(separator: "\n").map(String.init)
        // Base64 body lines should be at most 64 characters
        for line in lines {
            if !line.hasPrefix("-----") && !line.hasPrefix("=") && !line.isEmpty
                && !line.contains(":") {
                XCTAssertLessThanOrEqual(line.count, 64,
                    "Base64 line should not exceed 64 chars: \(line)")
            }
        }
    }

    // MARK: - Trailing Whitespace

    func testTrailingWhitespace() throws {
        let data = Data(repeating: 0xAB, count: 32)
        let armor = ArmorCodec.encode(data, type: .publicKey)

        // Add trailing whitespace after the footer
        let padded = armor + "\n\n"

        let (decoded, type, _) = try ArmorCodec.decode(padded)
        XCTAssertEqual(decoded, data)
        XCTAssertEqual(type, .publicKey)
    }
}
