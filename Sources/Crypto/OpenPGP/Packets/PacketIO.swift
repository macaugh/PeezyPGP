// PacketIO.swift
// PeezyPGP - Privacy-First OpenPGP
//
// OpenPGP packet serialization/deserialization per RFC 9580
// Handles both old and new packet formats

import Foundation

// MARK: - Packet Header Format

/// Represents a parsed OpenPGP packet
public struct OpenPGPPacket {
    public let tag: PacketTag
    public let body: Data
    public let isNewFormat: Bool

    public init(tag: PacketTag, body: Data, isNewFormat: Bool = true) {
        self.tag = tag
        self.body = body
        self.isNewFormat = isNewFormat
    }
}

// MARK: - Packet Reader

/// Reads OpenPGP packets from binary data
public final class PacketReader {

    private var data: Data
    private var offset: Int = 0

    public init(data: Data) {
        self.data = data
    }

    /// Check if there's more data to read
    public var hasMorePackets: Bool {
        return offset < data.count
    }

    /// Read the next packet
    public func readPacket() throws -> OpenPGPPacket {
        guard offset < data.count else {
            throw CryptoError.invalidPacket("Unexpected end of data")
        }

        let headerByte = data[offset]
        offset += 1

        // Check packet tag bit (bit 7 must be set)
        guard headerByte & 0x80 != 0 else {
            throw CryptoError.invalidPacket("Invalid packet header - bit 7 not set")
        }

        // Determine format (bit 6)
        let isNewFormat = headerByte & 0x40 != 0

        if isNewFormat {
            return try readNewFormatPacket(headerByte: headerByte)
        } else {
            return try readOldFormatPacket(headerByte: headerByte)
        }
    }

    /// Read all packets
    public func readAllPackets() throws -> [OpenPGPPacket] {
        var packets: [OpenPGPPacket] = []
        while hasMorePackets {
            packets.append(try readPacket())
        }
        return packets
    }

    // MARK: - New Format Packets (RFC 9580)

    private func readNewFormatPacket(headerByte: UInt8) throws -> OpenPGPPacket {
        // Tag is in bits 0-5
        let tagValue = headerByte & 0x3F
        guard let tag = PacketTag(rawValue: tagValue) else {
            throw CryptoError.invalidPacket("Unknown packet tag: \(tagValue)")
        }

        // Read length
        let bodyLength = try readNewFormatLength()

        // Read body
        guard offset + bodyLength <= data.count else {
            throw CryptoError.invalidPacket("Packet body truncated")
        }

        let body = data[offset..<(offset + bodyLength)]
        offset += bodyLength

        return OpenPGPPacket(tag: tag, body: Data(body), isNewFormat: true)
    }

    private func readNewFormatLength() throws -> Int {
        guard offset < data.count else {
            throw CryptoError.invalidPacket("Truncated length")
        }

        let firstByte = data[offset]
        offset += 1

        if firstByte < 192 {
            // One-octet length
            return Int(firstByte)
        } else if firstByte < 224 {
            // Two-octet length
            guard offset < data.count else {
                throw CryptoError.invalidPacket("Truncated length")
            }
            let secondByte = data[offset]
            offset += 1
            return ((Int(firstByte) - 192) << 8) + Int(secondByte) + 192
        } else if firstByte == 255 {
            // Five-octet length
            guard offset + 4 <= data.count else {
                throw CryptoError.invalidPacket("Truncated length")
            }
            let length = UInt32(data[offset]) << 24 |
                         UInt32(data[offset + 1]) << 16 |
                         UInt32(data[offset + 2]) << 8 |
                         UInt32(data[offset + 3])
            offset += 4
            return Int(length)
        } else {
            // Partial body length (for streaming)
            let partialLength = 1 << (Int(firstByte) & 0x1F)
            // For simplicity, we don't support partial body lengths in this implementation
            // A full implementation would need to handle streaming
            throw CryptoError.unsupportedAlgorithm("Partial body lengths not supported")
        }
    }

    // MARK: - Old Format Packets (Legacy)

    private func readOldFormatPacket(headerByte: UInt8) throws -> OpenPGPPacket {
        // Tag is in bits 2-5
        let tagValue = (headerByte & 0x3C) >> 2
        guard let tag = PacketTag(rawValue: tagValue) else {
            throw CryptoError.invalidPacket("Unknown packet tag: \(tagValue)")
        }

        // Length type is in bits 0-1
        let lengthType = headerByte & 0x03
        let bodyLength = try readOldFormatLength(lengthType: lengthType)

        // Read body
        guard offset + bodyLength <= data.count else {
            throw CryptoError.invalidPacket("Packet body truncated")
        }

        let body = data[offset..<(offset + bodyLength)]
        offset += bodyLength

        return OpenPGPPacket(tag: tag, body: Data(body), isNewFormat: false)
    }

    private func readOldFormatLength(lengthType: UInt8) throws -> Int {
        switch lengthType {
        case 0:
            // One-octet length
            guard offset < data.count else {
                throw CryptoError.invalidPacket("Truncated length")
            }
            let length = Int(data[offset])
            offset += 1
            return length

        case 1:
            // Two-octet length
            guard offset + 2 <= data.count else {
                throw CryptoError.invalidPacket("Truncated length")
            }
            let length = Int(data[offset]) << 8 | Int(data[offset + 1])
            offset += 2
            return length

        case 2:
            // Four-octet length
            guard offset + 4 <= data.count else {
                throw CryptoError.invalidPacket("Truncated length")
            }
            let length = Int(data[offset]) << 24 |
                         Int(data[offset + 1]) << 16 |
                         Int(data[offset + 2]) << 8 |
                         Int(data[offset + 3])
            offset += 4
            return length

        case 3:
            // Indeterminate length - read until end
            let remaining = data.count - offset
            return remaining

        default:
            throw CryptoError.invalidPacket("Invalid length type")
        }
    }
}

// MARK: - Packet Writer

/// Writes OpenPGP packets to binary data
public final class PacketWriter {

    private var buffer: Data = Data()

    public init() {}

    /// Get the accumulated data
    public var data: Data {
        return buffer
    }

    /// Reset the buffer
    public func reset() {
        buffer = Data()
    }

    /// Write a packet
    public func writePacket(_ packet: OpenPGPPacket) {
        writePacket(tag: packet.tag, body: packet.body)
    }

    /// Write a packet with tag and body
    public func writePacket(tag: PacketTag, body: Data) {
        // Always use new format (RFC 9580)
        let headerByte: UInt8 = 0xC0 | tag.rawValue
        buffer.append(headerByte)

        // Write length
        writeNewFormatLength(body.count)

        // Write body
        buffer.append(body)
    }

    private func writeNewFormatLength(_ length: Int) {
        if length < 192 {
            // One-octet
            buffer.append(UInt8(length))
        } else if length < 8384 {
            // Two-octet
            let adjusted = length - 192
            buffer.append(UInt8((adjusted >> 8) + 192))
            buffer.append(UInt8(adjusted & 0xFF))
        } else {
            // Five-octet
            buffer.append(0xFF)
            buffer.append(UInt8((length >> 24) & 0xFF))
            buffer.append(UInt8((length >> 16) & 0xFF))
            buffer.append(UInt8((length >> 8) & 0xFF))
            buffer.append(UInt8(length & 0xFF))
        }
    }

    // MARK: - Convenience Methods

    /// Write a public key packet
    public func writePublicKeyPacket(
        version: KeyVersion,
        creationTime: Date,
        algorithm: PublicKeyAlgorithm,
        publicKeyMaterial: Data,
        isSubkey: Bool = false
    ) {
        var body = Data()

        // Version
        body.append(version.rawValue)

        // Creation time (4 bytes, big-endian)
        let timestamp = UInt32(creationTime.timeIntervalSince1970)
        body.append(contentsOf: withUnsafeBytes(of: timestamp.bigEndian) { Array($0) })

        // Algorithm
        body.append(algorithm.rawValue)

        // Public key material
        body.append(publicKeyMaterial)

        let tag: PacketTag = isSubkey ? .publicSubkey : .publicKey
        writePacket(tag: tag, body: body)
    }

    /// Write a User ID packet
    public func writeUserIDPacket(userID: String) {
        guard let data = userID.data(using: .utf8) else { return }
        writePacket(tag: .userID, body: data)
    }

    /// Write a signature packet (simplified)
    public func writeSignaturePacket(signatureData: Data) {
        writePacket(tag: .signature, body: signatureData)
    }
}

// MARK: - MPI (Multi-Precision Integer) Handling

/// Utilities for OpenPGP MPI encoding
public enum MPICodec {

    /// Encode bytes as OpenPGP MPI
    /// MPI format: 2-byte bit count (big-endian) followed by the bytes
    public static func encode(_ bytes: Data) -> Data {
        // Remove leading zeros
        var stripped = bytes
        while stripped.first == 0 && stripped.count > 1 {
            stripped = stripped.dropFirst()
        }

        // Calculate bit count
        let bitCount: UInt16
        if let firstByte = stripped.first {
            let leadingBits = 8 - firstByte.leadingZeroBitCount
            bitCount = UInt16((stripped.count - 1) * 8 + leadingBits)
        } else {
            bitCount = 0
        }

        var result = Data()
        result.append(UInt8(bitCount >> 8))
        result.append(UInt8(bitCount & 0xFF))
        result.append(stripped)

        return result
    }

    /// Decode OpenPGP MPI
    /// Returns (mpi bytes, bytes consumed)
    public static func decode(from data: Data, at offset: Int) throws -> (Data, Int) {
        guard offset + 2 <= data.count else {
            throw CryptoError.invalidPacket("MPI truncated")
        }

        let bitCount = Int(data[offset]) << 8 | Int(data[offset + 1])
        let byteCount = (bitCount + 7) / 8

        guard offset + 2 + byteCount <= data.count else {
            throw CryptoError.invalidPacket("MPI data truncated")
        }

        let mpiData = data[(offset + 2)..<(offset + 2 + byteCount)]
        return (Data(mpiData), 2 + byteCount)
    }
}
