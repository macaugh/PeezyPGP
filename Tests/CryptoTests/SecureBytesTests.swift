// SecureBytesTests.swift
// PeezyPGP Tests

import XCTest
@testable import PeezyPGP

final class SecureBytesTests: XCTestCase {

    // MARK: - Initialization

    func testInitRandomBytes() {
        let sb = SecureBytes(randomBytes: 32)
        XCTAssertEqual(sb.count, 32)
        XCTAssertFalse(sb.isEmpty)

        // Random bytes should not be all zeros (astronomically unlikely)
        let allZero = SecureBytes(zeroedCount: 32)
        XCTAssertFalse(sb.constantTimeEquals(allZero))

        sb.zeroAndDeallocate()
        allZero.zeroAndDeallocate()
    }

    func testInitFromBytes() {
        let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let sb = SecureBytes(bytes: bytes)

        XCTAssertEqual(sb.count, 4)
        let result = sb.toBytes()
        XCTAssertEqual(result, bytes)

        sb.zeroAndDeallocate()
    }

    func testInitFromData() {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let sb = SecureBytes(data: data)

        XCTAssertEqual(sb.count, 4)
        XCTAssertEqual(sb.toData(), data)

        sb.zeroAndDeallocate()
    }

    func testInitZeroedCount() {
        let sb = SecureBytes(zeroedCount: 16)

        XCTAssertEqual(sb.count, 16)
        let bytes = sb.toBytes()
        XCTAssertTrue(bytes.allSatisfy { $0 == 0 })

        sb.zeroAndDeallocate()
    }

    func testInitEmptyBytes() {
        let sb = SecureBytes(bytes: [])
        XCTAssertEqual(sb.count, 0)
        XCTAssertTrue(sb.isEmpty)

        sb.zeroAndDeallocate()
    }

    func testInitEmptyData() {
        let sb = SecureBytes(data: Data())
        XCTAssertEqual(sb.count, 0)
        XCTAssertTrue(sb.isEmpty)

        sb.zeroAndDeallocate()
    }

    func testInitZeroedCountZero() {
        let sb = SecureBytes(zeroedCount: 0)
        XCTAssertEqual(sb.count, 0)
        XCTAssertTrue(sb.isEmpty)

        sb.zeroAndDeallocate()
    }

    // MARK: - Count and IsEmpty

    func testCountAndIsEmpty() {
        let empty = SecureBytes(bytes: [])
        XCTAssertEqual(empty.count, 0)
        XCTAssertTrue(empty.isEmpty)

        let nonEmpty = SecureBytes(randomBytes: 1)
        XCTAssertEqual(nonEmpty.count, 1)
        XCTAssertFalse(nonEmpty.isEmpty)

        empty.zeroAndDeallocate()
        nonEmpty.zeroAndDeallocate()
    }

    // MARK: - toData / toBytes Round-Trips

    func testToDataRoundTrip() {
        let original: [UInt8] = [0x10, 0x20, 0x30, 0x40, 0x50]
        let sb = SecureBytes(bytes: original)

        let data = sb.toData()
        let sb2 = SecureBytes(data: data)

        XCTAssertTrue(sb.constantTimeEquals(sb2))

        sb.zeroAndDeallocate()
        sb2.zeroAndDeallocate()
    }

    func testToBytesRoundTrip() {
        let original: [UInt8] = [0xAA, 0xBB, 0xCC]
        let sb = SecureBytes(bytes: original)

        let bytes = sb.toBytes()
        let sb2 = SecureBytes(bytes: bytes)

        XCTAssertTrue(sb.constantTimeEquals(sb2))

        sb.zeroAndDeallocate()
        sb2.zeroAndDeallocate()
    }

    // MARK: - Constant-Time Equals

    func testConstantTimeEqualsIdentical() {
        let a = SecureBytes(bytes: [0x01, 0x02, 0x03])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x03])

        XCTAssertTrue(a.constantTimeEquals(b))

        a.zeroAndDeallocate()
        b.zeroAndDeallocate()
    }

    func testConstantTimeEqualsDifferent() {
        let a = SecureBytes(bytes: [0x01, 0x02, 0x03])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x04])

        XCTAssertFalse(a.constantTimeEquals(b))

        a.zeroAndDeallocate()
        b.zeroAndDeallocate()
    }

    func testConstantTimeEqualsDifferentLength() {
        let a = SecureBytes(bytes: [0x01, 0x02])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x03])

        XCTAssertFalse(a.constantTimeEquals(b))

        a.zeroAndDeallocate()
        b.zeroAndDeallocate()
    }

    // MARK: - zeroAndDeallocate Idempotency

    func testZeroAndDeallocateIdempotent() {
        let sb = SecureBytes(randomBytes: 32)

        // Calling zeroAndDeallocate multiple times should not crash
        sb.zeroAndDeallocate()
        sb.zeroAndDeallocate()
        sb.zeroAndDeallocate()
    }

    // MARK: - withUnsafeBytes / withUnsafeMutableBytes

    func testWithUnsafeBytes() {
        let bytes: [UInt8] = [0xCA, 0xFE]
        let sb = SecureBytes(bytes: bytes)

        let result: [UInt8] = sb.withUnsafeBytes { buffer in
            Array(buffer)
        }

        XCTAssertEqual(result, bytes)

        sb.zeroAndDeallocate()
    }

    func testWithUnsafeMutableBytes() {
        let sb = SecureBytes(zeroedCount: 4)

        sb.withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: UInt8(0xFF), toByteOffset: 0, as: UInt8.self)
            buffer.storeBytes(of: UInt8(0xAA), toByteOffset: 1, as: UInt8.self)
        }

        let result = sb.toBytes()
        XCTAssertEqual(result[0], 0xFF)
        XCTAssertEqual(result[1], 0xAA)
        XCTAssertEqual(result[2], 0x00)
        XCTAssertEqual(result[3], 0x00)

        sb.zeroAndDeallocate()
    }

    // MARK: - Data.zero() Extension

    func testDataZero() {
        var data = Data([0x01, 0x02, 0x03, 0x04])
        data.zero()

        XCTAssertTrue(data.allSatisfy { $0 == 0 })
    }

    func testDataZeroEmpty() {
        var data = Data()
        data.zero() // Should not crash
        XCTAssertTrue(data.isEmpty)
    }

    // MARK: - [UInt8].zero() Extension

    func testBytesZero() {
        var bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        bytes.zero()

        XCTAssertTrue(bytes.allSatisfy { $0 == 0 })
    }

    func testBytesZeroEmpty() {
        var bytes: [UInt8] = []
        bytes.zero() // Should not crash
        XCTAssertTrue(bytes.isEmpty)
    }
}
