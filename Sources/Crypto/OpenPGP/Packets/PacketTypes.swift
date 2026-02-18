// PacketTypes.swift
// PeezyPGP - Privacy-First OpenPGP
//
// OpenPGP packet type definitions per RFC 9580
// Supports v6 key formats and modern algorithms

import Foundation

// MARK: - Packet Tags (RFC 9580 Section 5)

/// OpenPGP packet type tags
public enum PacketTag: UInt8 {
    case reserved = 0
    case publicKeyEncryptedSessionKey = 1   // PKESK
    case signature = 2
    case symmetricKeyEncryptedSessionKey = 3 // SKESK
    case onePassSignature = 4
    case secretKey = 5
    case publicKey = 6
    case secretSubkey = 7
    case compressedData = 8
    case symmetricallyEncryptedData = 9     // Deprecated
    case marker = 10
    case literalData = 11
    case trust = 12
    case userID = 13
    case publicSubkey = 14
    case userAttribute = 17
    case seipd = 18                          // Sym Encrypted Integrity Protected Data
    case mdc = 19                            // Modification Detection Code (deprecated)
    case aead = 20                           // AEAD Encrypted Data (RFC 9580)
    case padding = 21
}

// MARK: - Algorithm Identifiers

/// Public key algorithm IDs (RFC 9580 Section 9.1)
public enum PublicKeyAlgorithm: UInt8 {
    case rsaEncryptSign = 1
    case rsaEncryptOnly = 2
    case rsaSignOnly = 3
    case elgamalEncryptOnly = 16
    case dsa = 17
    case ecdh = 18
    case ecdsa = 19
    case elgamalEncryptSign = 20  // Deprecated
    case ed25519Legacy = 22       // EdDSA (legacy)
    case x25519 = 25              // X25519 (RFC 9580)
    case ed25519 = 27             // Ed25519 (RFC 9580)
}

/// Symmetric algorithm IDs (RFC 9580 Section 9.3)
public enum SymmetricAlgorithm: UInt8 {
    case plaintext = 0
    case idea = 1
    case tripleDES = 2
    case cast5 = 3
    case blowfish = 4
    case aes128 = 7
    case aes192 = 8
    case aes256 = 9
    case twofish = 10
    case camellia128 = 11
    case camellia192 = 12
    case camellia256 = 13

    /// Key size in bytes
    var keySize: Int {
        switch self {
        case .plaintext: return 0
        case .idea, .cast5, .blowfish: return 16
        case .tripleDES: return 24
        case .aes128, .camellia128: return 16
        case .aes192, .camellia192: return 24
        case .aes256, .twofish, .camellia256: return 32
        }
    }

    /// Block size in bytes
    var blockSize: Int {
        switch self {
        case .plaintext: return 0
        case .idea, .tripleDES, .cast5, .blowfish: return 8
        case .aes128, .aes192, .aes256: return 16
        case .twofish, .camellia128, .camellia192, .camellia256: return 16
        }
    }
}

/// Hash algorithm IDs (RFC 9580 Section 9.4)
public enum HashAlgorithm: UInt8 {
    case md5 = 1        // Deprecated - do not use
    case sha1 = 2       // Deprecated for signatures
    case ripemd160 = 3
    case sha256 = 8
    case sha384 = 9
    case sha512 = 10
    case sha224 = 11
    case sha3_256 = 12
    case sha3_512 = 14

    /// Digest size in bytes
    var digestSize: Int {
        switch self {
        case .md5: return 16
        case .sha1, .ripemd160: return 20
        case .sha224: return 28
        case .sha256, .sha3_256: return 32
        case .sha384: return 48
        case .sha512, .sha3_512: return 64
        }
    }
}

/// AEAD algorithm IDs (RFC 9580 Section 9.6)
public enum AEADAlgorithm: UInt8 {
    case eax = 1
    case ocb = 2
    case gcm = 3

    /// Nonce/IV size in bytes
    var nonceSize: Int {
        switch self {
        case .eax: return 16
        case .ocb: return 15
        case .gcm: return 12
        }
    }

    /// Authentication tag size in bytes
    var tagSize: Int {
        return 16
    }
}

// MARK: - S2K (String-to-Key) Specifiers

/// S2K type IDs (RFC 9580 Section 3.7)
public enum S2KType: UInt8 {
    case simple = 0         // Deprecated
    case salted = 1         // Deprecated
    case iterated = 3       // Legacy
    case argon2 = 4         // Preferred (RFC 9580)
}

/// S2K specifier for key derivation
public struct S2KSpecifier {
    public let type: S2KType
    public let hashAlgorithm: HashAlgorithm
    public let salt: Data
    public let iterations: UInt32       // For iterated S2K
    public let argon2Params: Argon2Parameters?  // For Argon2

    /// Argon2 parameters per RFC 9580
    public struct Argon2Parameters {
        public let parallelism: UInt8   // p (1-255)
        public let tagLength: UInt8     // T (tag length, typically 32)
        public let memoryExponent: UInt8 // m (memory = 2^m KiB)
        public let iterations: UInt8    // t (time cost)

        /// Memory in KiB
        public var memoryKiB: Int {
            return 1 << Int(memoryExponent)
        }

        /// Default secure parameters
        public static let `default` = Argon2Parameters(
            parallelism: 4,
            tagLength: 32,
            memoryExponent: 19,  // 512 MiB
            iterations: 3
        )

        /// Mobile-optimized parameters (less memory)
        public static let mobile = Argon2Parameters(
            parallelism: 4,
            tagLength: 32,
            memoryExponent: 16,  // 64 MiB
            iterations: 4
        )
    }

    /// Create an Argon2 S2K specifier (recommended)
    public static func argon2(params: Argon2Parameters = .default) -> S2KSpecifier {
        // Generate random 16-byte salt
        var salt = Data(count: 16)
        _ = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 16, buffer.baseAddress!)
        }

        return S2KSpecifier(
            type: .argon2,
            hashAlgorithm: .sha256,  // Not used for Argon2 but required
            salt: salt,
            iterations: 0,
            argon2Params: params
        )
    }

    /// Create an iterated S2K specifier (legacy compatibility)
    public static func iterated(
        hashAlgorithm: HashAlgorithm = .sha256,
        iterations: UInt32 = 65536
    ) -> S2KSpecifier {
        var salt = Data(count: 8)
        _ = salt.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, 8, buffer.baseAddress!)
        }

        return S2KSpecifier(
            type: .iterated,
            hashAlgorithm: hashAlgorithm,
            salt: salt,
            iterations: iterations,
            argon2Params: nil
        )
    }
}

// MARK: - Key Flags

/// Key capability flags (RFC 9580 Section 5.2.3.29)
public struct KeyFlags: OptionSet {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Key may be used to certify other keys
    public static let certify = KeyFlags(rawValue: 0x01)

    /// Key may be used to sign data
    public static let sign = KeyFlags(rawValue: 0x02)

    /// Key may be used to encrypt communications
    public static let encryptCommunications = KeyFlags(rawValue: 0x04)

    /// Key may be used to encrypt storage
    public static let encryptStorage = KeyFlags(rawValue: 0x08)

    /// Private key may have been split by secret sharing
    public static let splitKey = KeyFlags(rawValue: 0x10)

    /// Key may be used for authentication
    public static let authentication = KeyFlags(rawValue: 0x20)

    /// Private key may be in possession of multiple parties
    public static let groupKey = KeyFlags(rawValue: 0x80)

    /// Standard flags for primary signing key
    public static let primaryKey: KeyFlags = [.certify, .sign]

    /// Standard flags for encryption subkey
    public static let encryptionSubkey: KeyFlags = [.encryptCommunications, .encryptStorage]
}

// MARK: - Signature Types

/// Signature type IDs (RFC 9580 Section 5.2.1)
public enum SignatureType: UInt8 {
    case binaryDocument = 0x00
    case textDocument = 0x01
    case standalone = 0x02
    case genericCertification = 0x10
    case personaCertification = 0x11
    case casualCertification = 0x12
    case positiveCertification = 0x13
    case subkeyBinding = 0x18
    case primaryKeyBinding = 0x19
    case directKey = 0x1F
    case keyRevocation = 0x20
    case subkeyRevocation = 0x28
    case certificationRevocation = 0x30
    case timestamp = 0x40
    case thirdPartyConfirmation = 0x50
}

// MARK: - Key Packet Version

/// OpenPGP key packet version
public enum KeyVersion: UInt8 {
    case v4 = 4
    case v6 = 6  // RFC 9580
}
