// ArmorCodec.swift
// PeezyPGP - Privacy-First OpenPGP
//
// ASCII Armor encoding/decoding per RFC 4880 Section 6
// Provides human-readable representation of OpenPGP data

import Foundation

/// OpenPGP ASCII Armor types
public enum ArmorType: String {
    case publicKey = "PUBLIC KEY BLOCK"
    case privateKey = "PRIVATE KEY BLOCK"
    case message = "MESSAGE"
    case signature = "SIGNATURE"
    case signedMessage = "SIGNED MESSAGE"

    /// Header line
    var header: String {
        "-----BEGIN PGP \(rawValue)-----"
    }

    /// Footer line
    var footer: String {
        "-----END PGP \(rawValue)-----"
    }
}

/// OpenPGP ASCII Armor encoder and decoder
public enum ArmorCodec {

    // MARK: - Constants

    /// Line length for base64 output (per RFC 4880)
    private static let lineLength = 64

    /// CRC24 polynomial
    private static let crc24Init: UInt32 = 0xB704CE
    private static let crc24Poly: UInt32 = 0x1864CFB

    // MARK: - Encoding

    /// Encode binary data to ASCII armor
    /// - Parameters:
    ///   - data: Binary OpenPGP data
    ///   - type: Armor type (public key, message, etc.)
    ///   - headers: Optional armor headers (e.g., "Version: PeezyPGP")
    /// - Returns: ASCII armored string
    public static func encode(
        _ data: Data,
        type: ArmorType,
        headers: [String: String] = [:]
    ) -> String {
        var lines: [String] = []

        // Header
        lines.append(type.header)

        // Armor headers
        for (key, value) in headers.sorted(by: { $0.key < $1.key }) {
            lines.append("\(key): \(value)")
        }

        // Blank line separating headers from body
        lines.append("")

        // Base64 body with line wrapping
        let base64 = data.base64EncodedString()
        for i in stride(from: 0, to: base64.count, by: lineLength) {
            let start = base64.index(base64.startIndex, offsetBy: i)
            let end = base64.index(start, offsetBy: min(lineLength, base64.count - i))
            lines.append(String(base64[start..<end]))
        }

        // CRC24 checksum
        let crc = crc24(data)
        let crcData = Data([
            UInt8((crc >> 16) & 0xFF),
            UInt8((crc >> 8) & 0xFF),
            UInt8(crc & 0xFF)
        ])
        lines.append("=" + crcData.base64EncodedString())

        // Footer
        lines.append(type.footer)

        return lines.joined(separator: "\n")
    }

    // MARK: - Decoding

    /// Decode ASCII armor to binary data
    /// - Parameter armor: ASCII armored string
    /// - Returns: Tuple of (binary data, armor type, headers)
    /// - Throws: CryptoError if armor is invalid
    public static func decode(_ armor: String) throws -> (data: Data, type: ArmorType, headers: [String: String]) {
        let lines = armor.split(separator: "\n", omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .carriageReturn) }

        // Find header line
        guard let headerIndex = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN PGP ") }) else {
            throw CryptoError.armorFormatError("Missing armor header")
        }

        // Parse armor type from header
        let headerLine = lines[headerIndex]
        guard let armorType = parseArmorType(from: headerLine) else {
            throw CryptoError.armorFormatError("Unknown armor type")
        }

        // Find footer line
        let expectedFooter = armorType.footer
        guard let footerIndex = lines.lastIndex(where: { $0 == expectedFooter }) else {
            throw CryptoError.armorFormatError("Missing armor footer")
        }

        guard footerIndex > headerIndex else {
            throw CryptoError.armorFormatError("Footer before header")
        }

        // Parse armor headers (lines between header and blank line)
        var headers: [String: String] = [:]
        var bodyStartIndex = headerIndex + 1

        for i in (headerIndex + 1)..<footerIndex {
            let line = lines[i]
            if line.isEmpty {
                bodyStartIndex = i + 1
                break
            }
            if let colonIndex = line.firstIndex(of: ":") {
                let key = String(line[..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
            bodyStartIndex = i + 1
        }

        // Extract base64 body (everything between headers and checksum)
        var base64Lines: [String] = []
        var checksumLine: String?

        for i in bodyStartIndex..<footerIndex {
            let line = lines[i]
            if line.hasPrefix("=") && line.count == 5 {
                // CRC24 checksum line
                checksumLine = String(line.dropFirst())
            } else if !line.isEmpty {
                base64Lines.append(line)
            }
        }

        // Decode base64
        let base64String = base64Lines.joined()
        guard let data = Data(base64Encoded: base64String, options: .ignoreUnknownCharacters) else {
            throw CryptoError.armorFormatError("Invalid base64 data")
        }

        // Verify checksum if present
        if let checksumLine = checksumLine {
            guard let checksumData = Data(base64Encoded: checksumLine) else {
                throw CryptoError.armorFormatError("Invalid checksum encoding")
            }

            guard checksumData.count == 3 else {
                throw CryptoError.armorFormatError("Invalid checksum length")
            }

            let expectedCRC = UInt32(checksumData[0]) << 16 |
                              UInt32(checksumData[1]) << 8 |
                              UInt32(checksumData[2])
            let actualCRC = crc24(data)

            guard expectedCRC == actualCRC else {
                throw CryptoError.checksumMismatch
            }
        }

        return (data, armorType, headers)
    }

    // MARK: - Helper Methods

    /// Parse armor type from header line
    private static func parseArmorType(from header: String) -> ArmorType? {
        if header.contains("PUBLIC KEY BLOCK") {
            return .publicKey
        } else if header.contains("PRIVATE KEY BLOCK") {
            return .privateKey
        } else if header.contains("SIGNED MESSAGE") {
            return .signedMessage
        } else if header.contains("MESSAGE") {
            return .message
        } else if header.contains("SIGNATURE") {
            return .signature
        }
        return nil
    }

    /// Calculate CRC24 checksum per RFC 4880
    private static func crc24(_ data: Data) -> UInt32 {
        var crc = crc24Init

        for byte in data {
            crc ^= UInt32(byte) << 16

            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 {
                    crc ^= crc24Poly
                }
            }
        }

        return crc & 0xFFFFFF
    }
}

// MARK: - String Extension for Carriage Return

private extension CharacterSet {
    static let carriageReturn = CharacterSet(charactersIn: "\r")
}

private extension String {
    func trimmingCharacters(in set: CharacterSet) -> String {
        var result = self
        while let first = result.unicodeScalars.first, set.contains(first) {
            result.removeFirst()
        }
        while let last = result.unicodeScalars.last, set.contains(last) {
            result.removeLast()
        }
        return result
    }
}
