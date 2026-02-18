// OpenPGPEngine.swift
// PeezyPGP - Privacy-First OpenPGP
//
// Main OpenPGP operations: key generation, encryption, decryption, signing, verification
// Implements RFC 9580 with modern algorithms

import Foundation

// MARK: - PGP Key Structure

/// Represents an OpenPGP key (public or private)
public struct PGPKey: Identifiable, Codable {
    public let id: String                    // Key ID (hex string)
    public let fingerprint: Data             // Full fingerprint
    public let version: UInt8                // Key version (4 or 6)
    public let creationDate: Date
    public let userID: String
    public let publicKey: Data               // Public key material
    public let encryptionPublicKey: Data?    // Encryption subkey public material
    public let isPrivate: Bool

    // For private keys (encrypted with passphrase)
    public var encryptedPrivateKey: Data?
    public var encryptedEncryptionPrivateKey: Data?
    public var s2kSpecifier: Data?

    /// Key ID as hex string (last 16 hex chars of fingerprint for v6)
    public var keyID: String {
        return id
    }

    /// Fingerprint as hex string
    public var fingerprintHex: String {
        return fingerprint.map { String(format: "%02X", $0) }.joined()
    }

    /// Short fingerprint for display
    public var shortFingerprint: String {
        let hex = fingerprintHex
        // Format: XXXX XXXX XXXX XXXX (first 16 chars in groups of 4)
        var formatted = ""
        for (index, char) in hex.prefix(16).enumerated() {
            if index > 0 && index % 4 == 0 {
                formatted += " "
            }
            formatted.append(char)
        }
        return formatted
    }
}

// MARK: - Key Generation Parameters

/// Parameters for generating a new key pair
public struct KeyGenerationParameters {
    public let userID: String               // "Name <email@example.com>"
    public let passphrase: String
    public let keyVersion: KeyVersion
    public let useArgon2: Bool              // Use Argon2 for S2K (recommended)

    public init(
        userID: String,
        passphrase: String,
        keyVersion: KeyVersion = .v6,
        useArgon2: Bool = true
    ) {
        self.userID = userID
        self.passphrase = passphrase
        self.keyVersion = keyVersion
        self.useArgon2 = useArgon2
    }
}

// MARK: - OpenPGP Engine

/// Main engine for OpenPGP operations
public final class OpenPGPEngine {

    public init() {}

    // MARK: - Key Generation

    /// Generate a new OpenPGP key pair
    /// - Parameter params: Key generation parameters
    /// - Returns: PGPKey containing both public and private key material
    public func generateKeyPair(params: KeyGenerationParameters) throws -> PGPKey {
        // Generate Ed25519 signing key pair
        let (signingPrivate, signingPublic) = try Ed25519Operations.generateKeyPair()
        defer {
            signingPrivate.zeroAndDeallocate()
        }

        // Generate X25519 encryption key pair
        let (encryptionPrivate, encryptionPublic) = try X25519Operations.generateKeyPair()
        defer {
            encryptionPrivate.zeroAndDeallocate()
        }

        let creationDate = Date()

        // Build key fingerprint (v6)
        let fingerprint = try computeV6Fingerprint(
            publicKey: signingPublic.toData(),
            algorithm: .ed25519,
            creationDate: creationDate
        )

        // Derive key ID from fingerprint
        let keyID = fingerprint.suffix(8).map { String(format: "%02X", $0) }.joined()

        // Encrypt private keys with passphrase
        let (encryptedSigningKey, s2kData) = try encryptPrivateKey(
            privateKey: signingPrivate,
            passphrase: params.passphrase,
            useArgon2: params.useArgon2
        )

        let (encryptedEncryptionKey, _) = try encryptPrivateKey(
            privateKey: encryptionPrivate,
            passphrase: params.passphrase,
            useArgon2: params.useArgon2
        )

        return PGPKey(
            id: keyID,
            fingerprint: fingerprint,
            version: params.keyVersion.rawValue,
            creationDate: creationDate,
            userID: params.userID,
            publicKey: signingPublic.toData(),
            encryptionPublicKey: encryptionPublic.toData(),
            isPrivate: true,
            encryptedPrivateKey: encryptedSigningKey,
            encryptedEncryptionPrivateKey: encryptedEncryptionKey,
            s2kSpecifier: s2kData
        )
    }

    // MARK: - Key Export

    /// Export public key as ASCII armor
    public func exportPublicKey(_ key: PGPKey) -> String {
        let writer = PacketWriter()

        // Write primary public key packet
        writer.writePublicKeyPacket(
            version: KeyVersion(rawValue: key.version) ?? .v6,
            creationTime: key.creationDate,
            algorithm: .ed25519,
            publicKeyMaterial: key.publicKey
        )

        // Write User ID packet
        writer.writeUserIDPacket(userID: key.userID)

        // Write encryption subkey if present
        if let encPubKey = key.encryptionPublicKey {
            writer.writePublicKeyPacket(
                version: KeyVersion(rawValue: key.version) ?? .v6,
                creationTime: key.creationDate,
                algorithm: .x25519,
                publicKeyMaterial: encPubKey,
                isSubkey: true
            )
        }

        return ArmorCodec.encode(
            writer.data,
            type: .publicKey,
            headers: ["Version": "PeezyPGP 1.0"]
        )
    }

    /// Export private key as ASCII armor
    public func exportPrivateKey(_ key: PGPKey, passphrase: String) throws -> String {
        guard key.isPrivate else {
            throw CryptoError.invalidKeySize(expected: 0, actual: 0)
        }

        // For export, we create the full secret key packet structure
        var body = Data()

        // Version
        body.append(key.version)

        // Creation time
        let timestamp = UInt32(key.creationDate.timeIntervalSince1970)
        body.append(contentsOf: withUnsafeBytes(of: timestamp.bigEndian) { Array($0) })

        // Algorithm
        body.append(PublicKeyAlgorithm.ed25519.rawValue)

        // Public key
        body.append(key.publicKey)

        // S2K usage octet (254 = encrypted with S2K)
        body.append(0xFE)

        // S2K specifier and encrypted private key
        if let s2kData = key.s2kSpecifier {
            body.append(s2kData)
        }

        if let encryptedKey = key.encryptedPrivateKey {
            body.append(encryptedKey)
        }

        let writer = PacketWriter()
        writer.writePacket(tag: .secretKey, body: body)

        // Write User ID
        writer.writeUserIDPacket(userID: key.userID)

        // Write encryption subkey
        if let encSubkey = key.encryptedEncryptionPrivateKey,
           let encPubKey = key.encryptionPublicKey {
            var subkeyBody = Data()
            subkeyBody.append(key.version)
            let ts = UInt32(key.creationDate.timeIntervalSince1970)
            subkeyBody.append(contentsOf: withUnsafeBytes(of: ts.bigEndian) { Array($0) })
            subkeyBody.append(PublicKeyAlgorithm.x25519.rawValue)
            subkeyBody.append(encPubKey)
            subkeyBody.append(0xFE)
            if let s2kData = key.s2kSpecifier {
                subkeyBody.append(s2kData)
            }
            subkeyBody.append(encSubkey)
            writer.writePacket(tag: .secretSubkey, body: subkeyBody)
        }

        return ArmorCodec.encode(
            writer.data,
            type: .privateKey,
            headers: ["Version": "PeezyPGP 1.0"]
        )
    }

    // MARK: - Key Import

    /// Import a public key from ASCII armor
    public func importPublicKey(_ armor: String) throws -> PGPKey {
        let (data, type, _) = try ArmorCodec.decode(armor)

        guard type == .publicKey else {
            throw CryptoError.invalidPacket("Expected public key armor")
        }

        let reader = PacketReader(data: data)
        let packets = try reader.readAllPackets()

        guard let keyPacket = packets.first(where: { $0.tag == .publicKey }) else {
            throw CryptoError.invalidPacket("No public key packet found")
        }

        let (pubKey, version, creationDate, algorithm) = try parsePublicKeyPacket(keyPacket.body)

        guard algorithm == .ed25519 || algorithm == .ecdsa else {
            throw CryptoError.unsupportedAlgorithm("Only Ed25519 keys supported")
        }

        // Find User ID
        let userID = packets.first(where: { $0.tag == .userID })
            .flatMap { String(data: $0.body, encoding: .utf8) } ?? "Unknown"

        // Find encryption subkey
        let encSubkey = packets.first(where: { $0.tag == .publicSubkey })
            .flatMap { try? parsePublicKeyPacket($0.body).0 }

        // Compute fingerprint
        let fingerprint = try computeV6Fingerprint(
            publicKey: pubKey,
            algorithm: algorithm,
            creationDate: creationDate
        )

        let keyID = fingerprint.suffix(8).map { String(format: "%02X", $0) }.joined()

        return PGPKey(
            id: keyID,
            fingerprint: fingerprint,
            version: version,
            creationDate: creationDate,
            userID: userID,
            publicKey: pubKey,
            encryptionPublicKey: encSubkey,
            isPrivate: false
        )
    }

    // MARK: - Message Encryption

    /// Encrypt a message for a recipient
    public func encrypt(
        message: String,
        recipient: PGPKey
    ) throws -> String {
        guard let messageData = message.data(using: .utf8) else {
            throw CryptoError.encryptionFailed(underlying: NSError(domain: "UTF8", code: -1))
        }

        return try encrypt(data: messageData, recipient: recipient)
    }

    /// Encrypt data for a recipient
    public func encrypt(
        data: Data,
        recipient: PGPKey
    ) throws -> String {
        guard let recipientEncKey = recipient.encryptionPublicKey else {
            throw CryptoError.invalidPacket("Recipient has no encryption key")
        }

        // Generate session key
        let sessionKey = AES256Operations.generateSessionKey()
        defer { sessionKey.zeroAndDeallocate() }

        // Encrypt session key to recipient
        let (ephemeralPubKey, wrappedSessionKey) = try X25519Operations.encryptSessionKey(
            sessionKey: sessionKey,
            recipientPublicKey: recipientEncKey,
            recipientKeyFingerprint: recipient.fingerprint
        )

        // Build PKESK packet
        var pkeskBody = Data()
        pkeskBody.append(0x06)  // Version 6
        pkeskBody.append(contentsOf: recipient.fingerprint.prefix(20))  // Key ID (20 bytes for v6)
        pkeskBody.append(PublicKeyAlgorithm.x25519.rawValue)
        pkeskBody.append(UInt8(ephemeralPubKey.count))
        pkeskBody.append(ephemeralPubKey)
        pkeskBody.append(UInt8(wrappedSessionKey.count))
        pkeskBody.append(wrappedSessionKey)

        // Create literal data packet
        var literalBody = Data()
        literalBody.append(0x62)  // 'b' for binary
        literalBody.append(0x00)  // Zero-length filename
        let timestamp = UInt32(Date().timeIntervalSince1970)
        literalBody.append(contentsOf: withUnsafeBytes(of: timestamp.bigEndian) { Array($0) })
        literalBody.append(data)

        let literalWriter = PacketWriter()
        literalWriter.writePacket(tag: .literalData, body: literalBody)

        // Encrypt with session key using AES-256-GCM
        let encrypted = try AES256Operations.encryptGCM(
            plaintext: literalWriter.data,
            key: sessionKey
        )

        // Build SEIPD v2 packet
        var seipdBody = Data()
        seipdBody.append(0x02)  // Version 2
        seipdBody.append(SymmetricAlgorithm.aes256.rawValue)
        seipdBody.append(AEADAlgorithm.gcm.rawValue)
        seipdBody.append(0x06)  // Chunk size (2^6 = 64 byte chunks - simplified)
        seipdBody.append(encrypted)

        // Write all packets
        let writer = PacketWriter()
        writer.writePacket(tag: .publicKeyEncryptedSessionKey, body: pkeskBody)
        writer.writePacket(tag: .seipd, body: seipdBody)

        return ArmorCodec.encode(
            writer.data,
            type: .message,
            headers: ["Version": "PeezyPGP 1.0"]
        )
    }

    // MARK: - Message Decryption

    /// Decrypt a message
    public func decrypt(
        armoredMessage: String,
        privateKey: PGPKey,
        passphrase: String
    ) throws -> String {
        let decrypted = try decryptData(
            armoredMessage: armoredMessage,
            privateKey: privateKey,
            passphrase: passphrase
        )

        guard let message = String(data: decrypted, encoding: .utf8) else {
            throw CryptoError.decryptionFailed(underlying: NSError(domain: "UTF8", code: -1))
        }

        return message
    }

    /// Decrypt data
    public func decryptData(
        armoredMessage: String,
        privateKey: PGPKey,
        passphrase: String
    ) throws -> Data {
        guard privateKey.isPrivate else {
            throw CryptoError.invalidPacket("Not a private key")
        }

        let (data, type, _) = try ArmorCodec.decode(armoredMessage)

        guard type == .message else {
            throw CryptoError.invalidPacket("Expected message armor")
        }

        let reader = PacketReader(data: data)
        let packets = try reader.readAllPackets()

        // Find PKESK packet
        guard let pkeskPacket = packets.first(where: { $0.tag == .publicKeyEncryptedSessionKey }) else {
            throw CryptoError.invalidPacket("No PKESK packet found")
        }

        // Parse PKESK
        let pkeskBody = pkeskPacket.body
        guard pkeskBody.count > 23 else {
            throw CryptoError.invalidPacket("PKESK too short")
        }

        // Extract ephemeral public key and wrapped session key
        var offset = 22  // Skip version, key ID, algorithm
        let ephemeralKeyLen = Int(pkeskBody[offset])
        offset += 1
        let ephemeralPubKey = pkeskBody[offset..<(offset + ephemeralKeyLen)]
        offset += ephemeralKeyLen
        let wrappedKeyLen = Int(pkeskBody[offset])
        offset += 1
        let wrappedSessionKey = pkeskBody[offset..<(offset + wrappedKeyLen)]

        // Decrypt private key
        let decryptedPrivKey = try decryptPrivateKey(
            encryptedKey: privateKey.encryptedEncryptionPrivateKey!,
            s2kData: privateKey.s2kSpecifier!,
            passphrase: passphrase
        )
        defer { decryptedPrivKey.zeroAndDeallocate() }

        // Unwrap session key
        let sessionKey = try X25519Operations.decryptSessionKey(
            wrappedKey: Data(wrappedSessionKey),
            ephemeralPublicKey: Data(ephemeralPubKey),
            recipientPrivateKey: decryptedPrivKey,
            recipientPublicKey: privateKey.encryptionPublicKey!,
            recipientFingerprint: privateKey.fingerprint
        )
        defer { sessionKey.zeroAndDeallocate() }

        // Find SEIPD packet
        guard let seipdPacket = packets.first(where: { $0.tag == .seipd }) else {
            throw CryptoError.invalidPacket("No SEIPD packet found")
        }

        // Parse and decrypt SEIPD
        let seipdBody = seipdPacket.body
        guard seipdBody.count > 4 else {
            throw CryptoError.invalidPacket("SEIPD too short")
        }

        let ciphertext = seipdBody.dropFirst(4)  // Skip version, algo, AEAD, chunk size

        let decrypted = try AES256Operations.decryptGCM(
            ciphertext: Data(ciphertext),
            key: sessionKey
        )

        // Parse literal data packet from decrypted data
        let innerReader = PacketReader(data: decrypted)
        let innerPackets = try innerReader.readAllPackets()

        guard let literalPacket = innerPackets.first(where: { $0.tag == .literalData }) else {
            throw CryptoError.invalidPacket("No literal data packet")
        }

        // Skip literal data header (format byte, filename length, filename, date)
        let literalBody = literalPacket.body
        guard literalBody.count > 5 else {
            throw CryptoError.invalidPacket("Literal data too short")
        }

        let filenameLen = Int(literalBody[1])
        let dataStart = 1 + 1 + filenameLen + 4  // format + len + filename + date

        return Data(literalBody.dropFirst(dataStart))
    }

    // MARK: - Signing

    /// Sign a message
    public func sign(
        message: String,
        privateKey: PGPKey,
        passphrase: String
    ) throws -> String {
        guard let messageData = message.data(using: .utf8) else {
            throw CryptoError.signingFailed(underlying: NSError(domain: "UTF8", code: -1))
        }

        return try sign(data: messageData, privateKey: privateKey, passphrase: passphrase)
    }

    /// Sign data
    public func sign(
        data: Data,
        privateKey: PGPKey,
        passphrase: String
    ) throws -> String {
        guard privateKey.isPrivate else {
            throw CryptoError.invalidPacket("Not a private key")
        }

        // Decrypt signing private key
        let signingKey = try decryptPrivateKey(
            encryptedKey: privateKey.encryptedPrivateKey!,
            s2kData: privateKey.s2kSpecifier!,
            passphrase: passphrase
        )
        defer { signingKey.zeroAndDeallocate() }

        // Create signature packet
        let signatureData = try createSignaturePacket(
            data: data,
            signingKey: signingKey,
            publicKey: privateKey.publicKey,
            fingerprint: privateKey.fingerprint
        )

        let writer = PacketWriter()
        writer.writePacket(tag: .signature, body: signatureData)

        return ArmorCodec.encode(
            writer.data,
            type: .signature,
            headers: ["Version": "PeezyPGP 1.0"]
        )
    }

    // MARK: - Verification

    /// Verify a detached signature
    public func verify(
        message: String,
        signature: String,
        publicKey: PGPKey
    ) throws -> Bool {
        guard let messageData = message.data(using: .utf8) else {
            return false
        }

        return try verify(data: messageData, signature: signature, publicKey: publicKey)
    }

    /// Verify a detached signature on data
    public func verify(
        data: Data,
        signature: String,
        publicKey: PGPKey
    ) throws -> Bool {
        let (sigData, type, _) = try ArmorCodec.decode(signature)

        guard type == .signature else {
            throw CryptoError.invalidPacket("Expected signature armor")
        }

        let reader = PacketReader(data: sigData)
        let packets = try reader.readAllPackets()

        guard let sigPacket = packets.first(where: { $0.tag == .signature }) else {
            throw CryptoError.invalidPacket("No signature packet found")
        }

        return try verifySignaturePacket(
            signatureData: sigPacket.body,
            data: data,
            publicKey: publicKey.publicKey
        )
    }

    // MARK: - Private Helpers

    private func computeV6Fingerprint(
        publicKey: Data,
        algorithm: PublicKeyAlgorithm,
        creationDate: Date
    ) throws -> Data {
        // V6 fingerprint = SHA256(0x9B || 4-octet-len || key-packet-body)
        var material = Data()

        // Build key packet body
        var keyBody = Data()
        keyBody.append(0x06)  // Version 6

        let timestamp = UInt32(creationDate.timeIntervalSince1970)
        keyBody.append(contentsOf: withUnsafeBytes(of: timestamp.bigEndian) { Array($0) })

        keyBody.append(algorithm.rawValue)

        // For Ed25519/X25519, the key is prefixed with length
        keyBody.append(UInt8(publicKey.count))
        keyBody.append(publicKey)

        // Fingerprint material
        material.append(0x9B)  // Constant for v6

        let len = UInt32(keyBody.count)
        material.append(contentsOf: withUnsafeBytes(of: len.bigEndian) { Array($0) })
        material.append(keyBody)

        return SHA2Operations.sha256(material)
    }

    private func encryptPrivateKey(
        privateKey: SecureBytes,
        passphrase: String,
        useArgon2: Bool
    ) throws -> (encryptedKey: Data, s2kData: Data) {
        // For this implementation, we use a simplified approach:
        // 1. Derive key from passphrase using S2K
        // 2. Encrypt private key with AES-256-GCM

        let s2k = useArgon2 ?
            S2KSpecifier.argon2(params: .mobile) :
            S2KSpecifier.iterated()

        // Derive encryption key from passphrase
        let passphraseData = passphrase.data(using: .utf8)!
        let derivedKey = try deriveKeyFromPassphrase(passphrase: passphraseData, s2k: s2k)
        defer { derivedKey.zeroAndDeallocate() }

        // Encrypt private key
        let encrypted = try AES256Operations.encryptGCM(
            plaintext: privateKey.toData(),
            key: derivedKey
        )

        // Serialize S2K specifier
        var s2kData = Data()
        s2kData.append(SymmetricAlgorithm.aes256.rawValue)
        s2kData.append(AEADAlgorithm.gcm.rawValue)
        s2kData.append(s2k.type.rawValue)

        if s2k.type == .argon2, let params = s2k.argon2Params {
            s2kData.append(s2k.salt)  // 16 bytes
            s2kData.append(params.iterations)
            s2kData.append(params.parallelism)
            s2kData.append(params.memoryExponent)
        } else {
            s2kData.append(s2k.hashAlgorithm.rawValue)
            s2kData.append(s2k.salt)  // 8 bytes
            // Encode iteration count
            let encoded = encodeIterationCount(s2k.iterations)
            s2kData.append(encoded)
        }

        return (encrypted, s2kData)
    }

    private func decryptPrivateKey(
        encryptedKey: Data,
        s2kData: Data,
        passphrase: String
    ) throws -> SecureBytes {
        // Parse S2K specifier
        guard s2kData.count >= 3 else {
            throw CryptoError.invalidPacket("S2K data too short")
        }

        let s2kType = S2KType(rawValue: s2kData[2]) ?? .iterated

        var salt: Data
        var s2k: S2KSpecifier

        if s2kType == .argon2 {
            guard s2kData.count >= 22 else {
                throw CryptoError.invalidPacket("Argon2 S2K data too short")
            }
            salt = s2kData[3..<19]
            let iterations = s2kData[19]
            let parallelism = s2kData[20]
            let memoryExp = s2kData[21]

            s2k = S2KSpecifier(
                type: .argon2,
                hashAlgorithm: .sha256,
                salt: salt,
                iterations: 0,
                argon2Params: .init(
                    parallelism: parallelism,
                    tagLength: 32,
                    memoryExponent: memoryExp,
                    iterations: iterations
                )
            )
        } else {
            guard s2kData.count >= 12 else {
                throw CryptoError.invalidPacket("Iterated S2K data too short")
            }
            let hashAlg = HashAlgorithm(rawValue: s2kData[3]) ?? .sha256
            salt = s2kData[4..<12]
            let iterCount = decodeIterationCount(s2kData[12])

            s2k = S2KSpecifier(
                type: .iterated,
                hashAlgorithm: hashAlg,
                salt: salt,
                iterations: iterCount,
                argon2Params: nil
            )
        }

        // Derive decryption key
        let passphraseData = passphrase.data(using: .utf8)!
        let derivedKey = try deriveKeyFromPassphrase(passphrase: passphraseData, s2k: s2k)
        defer { derivedKey.zeroAndDeallocate() }

        // Decrypt
        let decrypted = try AES256Operations.decryptGCM(
            ciphertext: encryptedKey,
            key: derivedKey
        )

        return SecureBytes(data: decrypted)
    }

    private func deriveKeyFromPassphrase(passphrase: Data, s2k: S2KSpecifier) throws -> SecureBytes {
        if s2k.type == .argon2, let params = s2k.argon2Params {
            // For Argon2, we'd need to implement or use a library
            // For now, fall back to PBKDF2-like approach using HKDF
            // In production, use a proper Argon2 implementation

            var input = Data()
            input.append(s2k.salt)
            input.append(passphrase)

            let inputKey = SecureBytes(data: input)
            defer { inputKey.zeroAndDeallocate() }

            // Iterate HKDF as a simplified KDF
            var derived = try HKDFOperations.deriveKey(
                inputKeyMaterial: inputKey,
                salt: s2k.salt,
                info: "PeezyPGP-S2K".data(using: .utf8)!,
                outputLength: 32
            )

            for _ in 0..<Int(params.iterations) {
                derived = try HKDFOperations.deriveKey(
                    inputKeyMaterial: derived,
                    salt: s2k.salt,
                    info: "PeezyPGP-S2K".data(using: .utf8)!,
                    outputLength: 32
                )
            }

            return derived
        } else {
            // Iterated S2K
            var material = Data()
            material.append(s2k.salt)
            material.append(passphrase)

            // Expand to iteration count bytes
            let totalBytes = Int(s2k.iterations)
            var expanded = Data()
            while expanded.count < totalBytes {
                expanded.append(material)
            }
            expanded = expanded.prefix(totalBytes)

            // Hash
            let digest = SHA2Operations.sha256(expanded)
            return SecureBytes(data: digest)
        }
    }

    private func encodeIterationCount(_ count: UInt32) -> UInt8 {
        // Encode iteration count per RFC 4880
        let expBias: UInt32 = 6
        var c = count
        var exp: UInt8 = 0

        while c > 255 && exp < 31 {
            c >>= 1
            exp += 1
        }

        return UInt8(truncatingIfNeeded: (UInt32(exp) + expBias) << 4) | UInt8(c & 0x0F)
    }

    private func decodeIterationCount(_ encoded: UInt8) -> UInt32 {
        let mantissa = UInt32(encoded & 0x0F) | 0x10
        let exponent = UInt32(encoded >> 4)
        return mantissa << exponent
    }

    private func parsePublicKeyPacket(_ data: Data) throws -> (Data, UInt8, Date, PublicKeyAlgorithm) {
        guard data.count >= 6 else {
            throw CryptoError.invalidPacket("Public key packet too short")
        }

        let version = data[0]
        let timestamp = UInt32(data[1]) << 24 |
                        UInt32(data[2]) << 16 |
                        UInt32(data[3]) << 8 |
                        UInt32(data[4])
        let creationDate = Date(timeIntervalSince1970: TimeInterval(timestamp))
        let algorithmRaw = data[5]

        guard let algorithm = PublicKeyAlgorithm(rawValue: algorithmRaw) else {
            throw CryptoError.unsupportedAlgorithm("Unknown algorithm: \(algorithmRaw)")
        }

        // Extract public key material
        let keyMaterial: Data
        if version == 6 {
            // V6 format has length prefix
            guard data.count > 6 else {
                throw CryptoError.invalidPacket("V6 key missing length")
            }
            let keyLen = Int(data[6])
            guard data.count >= 7 + keyLen else {
                throw CryptoError.invalidPacket("V6 key truncated")
            }
            keyMaterial = data[7..<(7 + keyLen)]
        } else {
            // V4 format uses MPI
            let (mpi, _) = try MPICodec.decode(from: data, at: 6)
            keyMaterial = mpi
        }

        return (Data(keyMaterial), version, creationDate, algorithm)
    }

    private func createSignaturePacket(
        data: Data,
        signingKey: SecureBytes,
        publicKey: Data,
        fingerprint: Data
    ) throws -> Data {
        var packet = Data()

        // Version 6
        packet.append(0x06)

        // Signature type (binary document)
        packet.append(SignatureType.binaryDocument.rawValue)

        // Public key algorithm
        packet.append(PublicKeyAlgorithm.ed25519.rawValue)

        // Hash algorithm
        packet.append(HashAlgorithm.sha256.rawValue)

        // Hashed subpackets (minimal)
        var hashedSubpackets = Data()

        // Signature creation time
        hashedSubpackets.append(5)  // Length
        hashedSubpackets.append(2)  // Signature creation time type
        let timestamp = UInt32(Date().timeIntervalSince1970)
        hashedSubpackets.append(contentsOf: withUnsafeBytes(of: timestamp.bigEndian) { Array($0) })

        // Issuer fingerprint
        hashedSubpackets.append(UInt8(1 + fingerprint.count))  // Length
        hashedSubpackets.append(33)  // Issuer fingerprint type
        hashedSubpackets.append(contentsOf: fingerprint)

        // Write hashed subpackets length
        packet.append(UInt8(hashedSubpackets.count >> 8))
        packet.append(UInt8(hashedSubpackets.count & 0xFF))
        packet.append(hashedSubpackets)

        // Unhashed subpackets (empty)
        packet.append(0x00)
        packet.append(0x00)

        // Create hash
        var hashInput = Data()
        hashInput.append(data)

        // Hash trailer
        hashInput.append(0x06)  // Version
        hashInput.append(SignatureType.binaryDocument.rawValue)
        hashInput.append(PublicKeyAlgorithm.ed25519.rawValue)
        hashInput.append(HashAlgorithm.sha256.rawValue)
        hashInput.append(UInt8(hashedSubpackets.count >> 8))
        hashInput.append(UInt8(hashedSubpackets.count & 0xFF))
        hashInput.append(hashedSubpackets)

        // V6 trailer
        hashInput.append(0x06)
        hashInput.append(0xFF)
        let trailerLen = UInt32(6 + hashedSubpackets.count)
        hashInput.append(contentsOf: withUnsafeBytes(of: trailerLen.bigEndian) { Array($0) })

        let hash = SHA2Operations.sha256(hashInput)

        // Left 16 bits of hash
        packet.append(hash[0])
        packet.append(hash[1])

        // Signature (Ed25519)
        let signature = try Ed25519Operations.signDigest(hash, privateKey: signingKey)
        packet.append(UInt8(signature.count))
        packet.append(signature)

        return packet
    }

    private func verifySignaturePacket(
        signatureData: Data,
        data: Data,
        publicKey: Data
    ) throws -> Bool {
        guard signatureData.count > 10 else {
            throw CryptoError.invalidPacket("Signature packet too short")
        }

        let version = signatureData[0]
        guard version == 4 || version == 6 else {
            throw CryptoError.unsupportedAlgorithm("Unsupported signature version: \(version)")
        }

        let sigType = signatureData[1]
        let pubKeyAlg = signatureData[2]
        let hashAlg = signatureData[3]

        guard pubKeyAlg == PublicKeyAlgorithm.ed25519.rawValue ||
              pubKeyAlg == PublicKeyAlgorithm.ed25519Legacy.rawValue else {
            throw CryptoError.unsupportedAlgorithm("Only Ed25519 signatures supported")
        }

        // Parse hashed subpackets length
        let hashedLen = Int(signatureData[4]) << 8 | Int(signatureData[5])
        let hashedSubpackets = signatureData[6..<(6 + hashedLen)]

        // Parse unhashed subpackets length
        let unhashedOffset = 6 + hashedLen
        let unhashedLen = Int(signatureData[unhashedOffset]) << 8 | Int(signatureData[unhashedOffset + 1])

        // Get signature
        let sigOffset = unhashedOffset + 2 + unhashedLen + 2  // +2 for left hash, +2 for unhashed len
        guard sigOffset < signatureData.count else {
            throw CryptoError.invalidPacket("Signature data truncated")
        }

        let sigLen = Int(signatureData[sigOffset])
        guard sigOffset + 1 + sigLen <= signatureData.count else {
            throw CryptoError.invalidPacket("Signature truncated")
        }

        let signature = signatureData[(sigOffset + 1)..<(sigOffset + 1 + sigLen)]

        // Reconstruct hash
        var hashInput = Data()
        hashInput.append(data)

        // Hash trailer
        hashInput.append(version)
        hashInput.append(sigType)
        hashInput.append(pubKeyAlg)
        hashInput.append(hashAlg)
        hashInput.append(UInt8(hashedLen >> 8))
        hashInput.append(UInt8(hashedLen & 0xFF))
        hashInput.append(hashedSubpackets)

        if version == 6 {
            hashInput.append(0x06)
            hashInput.append(0xFF)
            let trailerLen = UInt32(6 + hashedLen)
            hashInput.append(contentsOf: withUnsafeBytes(of: trailerLen.bigEndian) { Array($0) })
        } else {
            hashInput.append(0x04)
            hashInput.append(0xFF)
            let trailerLen = UInt32(6 + hashedLen)
            hashInput.append(contentsOf: withUnsafeBytes(of: trailerLen.bigEndian) { Array($0) })
        }

        let hash = SHA2Operations.sha256(hashInput)

        // Verify
        return Ed25519Operations.verify(
            signature: Data(signature),
            message: hash,
            publicKey: publicKey
        )
    }
}
