// SecureEnclaveManager.swift
// PeezyPGP - Privacy-First OpenPGP
//
// Hardware-backed key protection using Apple Secure Enclave
// Provides an additional layer of defense for key wrapping

import Foundation
import Security
import CryptoKit
import LocalAuthentication

// MARK: - Secure Enclave Error

public enum SecureEnclaveError: Error, LocalizedError {
    case notAvailable
    case keyGenerationFailed
    case keyNotFound
    case encryptionFailed
    case decryptionFailed
    case authenticationRequired
    case unexpectedError(String)

    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave not available on this device"
        case .keyGenerationFailed:
            return "Failed to generate Secure Enclave key"
        case .keyNotFound:
            return "Secure Enclave key not found"
        case .encryptionFailed:
            return "Secure Enclave encryption failed"
        case .decryptionFailed:
            return "Secure Enclave decryption failed"
        case .authenticationRequired:
            return "Authentication required for Secure Enclave access"
        case .unexpectedError(let message):
            return "Secure Enclave error: \(message)"
        }
    }
}

// MARK: - Secure Enclave Manager

/// Manages hardware-backed key encryption using Secure Enclave
///
/// Architecture:
/// 1. A P-256 key pair is created in Secure Enclave (never exportable)
/// 2. This key is used to wrap/unwrap AES keys
/// 3. The AES keys are used to encrypt the actual PGP private keys
///
/// This provides hardware-backed protection where the wrapping key
/// physically cannot be extracted from the device.
public final class SecureEnclaveManager {

    // MARK: - Properties

    /// Tag for the Secure Enclave key
    private let keyTag: String

    /// Whether to require biometric authentication
    private let requireBiometric: Bool

    /// Access group for shared access
    private let accessGroup: String?

    // MARK: - Initialization

    public init(
        keyTag: String = "com.peezypgp.secure-enclave.kek",
        requireBiometric: Bool = true,
        accessGroup: String? = nil
    ) {
        self.keyTag = keyTag
        self.requireBiometric = requireBiometric
        self.accessGroup = accessGroup
    }

    // MARK: - Availability

    /// Check if Secure Enclave is available
    public static var isAvailable: Bool {
        // Check for Secure Enclave support
        if #available(iOS 13.0, macOS 10.15, *) {
            return SecureEnclave.isAvailable
        }
        return false
    }

    // MARK: - Key Management

    /// Generate or retrieve the Secure Enclave key encryption key (KEK)
    /// This key never leaves the Secure Enclave
    public func ensureKEKExists() throws {
        // Check if key already exists
        if getSecureEnclaveKey() != nil {
            return
        }

        // Generate new key
        try generateSecureEnclaveKey()
    }

    /// Delete the Secure Enclave key
    public func deleteKEK() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: keyTag.data(using: .utf8)!,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.unexpectedError("Delete failed: \(status)")
        }
    }

    // MARK: - Encryption/Decryption

    /// Wrap (encrypt) data using Secure Enclave KEK
    /// Uses ECIES with the Secure Enclave P-256 key
    ///
    /// - Parameter data: Data to wrap (typically an AES key)
    /// - Returns: Wrapped data (ephemeral public key + ciphertext)
    public func wrap(_ data: SecureBytes) throws -> Data {
        guard let secKey = getSecureEnclaveKey() else {
            throw SecureEnclaveError.keyNotFound
        }

        // Get public key for encryption
        guard let publicKey = SecKeyCopyPublicKey(secKey) else {
            throw SecureEnclaveError.unexpectedError("Could not get public key")
        }

        // Encrypt using ECIES
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw SecureEnclaveError.encryptionFailed
        }

        let plaintext = data.toData()
        defer {
            var mutablePlaintext = plaintext
            mutablePlaintext.zero()
        }

        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            plaintext as CFData,
            &error
        ) as Data? else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown"
            throw SecureEnclaveError.unexpectedError(errorDescription)
        }

        return ciphertext
    }

    /// Unwrap (decrypt) data using Secure Enclave KEK
    /// Requires user authentication if configured
    ///
    /// - Parameters:
    ///   - wrappedData: Previously wrapped data
    ///   - authContext: Optional LAContext for authentication
    /// - Returns: Unwrapped data as SecureBytes
    public func unwrap(
        _ wrappedData: Data,
        authContext: LAContext? = nil
    ) throws -> SecureBytes {
        guard let secKey = getSecureEnclaveKey(authContext: authContext) else {
            throw SecureEnclaveError.keyNotFound
        }

        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

        guard SecKeyIsAlgorithmSupported(secKey, .decrypt, algorithm) else {
            throw SecureEnclaveError.decryptionFailed
        }

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            secKey,
            algorithm,
            wrappedData as CFData,
            &error
        ) as Data? else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown"
            if errorDescription.contains("authentication") ||
               errorDescription.contains("Authentication") {
                throw SecureEnclaveError.authenticationRequired
            }
            throw SecureEnclaveError.decryptionFailed
        }

        return SecureBytes(data: plaintext)
    }

    // MARK: - Private Helpers

    /// Generate a new Secure Enclave key
    private func generateSecureEnclaveKey() throws {
        var accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]

        if requireBiometric {
            accessControlFlags.insert(.biometryCurrentSet)
        }

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControlFlags,
            &error
        ) else {
            let errorDescription = error?.takeRetainedValue().localizedDescription ?? "Unknown"
            throw SecureEnclaveError.unexpectedError(errorDescription)
        }

        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: keyTag.data(using: .utf8)!,
                kSecAttrAccessControl: accessControl
            ] as [CFString: Any]
        ]

        if let group = accessGroup {
            attributes[kSecAttrAccessGroup] = group
        }

        var generationError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &generationError) != nil else {
            let errorDescription = generationError?.takeRetainedValue().localizedDescription ?? "Unknown"
            throw SecureEnclaveError.unexpectedError(errorDescription)
        }
    }

    /// Retrieve the Secure Enclave key
    private func getSecureEnclaveKey(authContext: LAContext? = nil) -> SecKey? {
        var query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: keyTag.data(using: .utf8)!,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef: true
        ]

        if let context = authContext {
            query[kSecUseAuthenticationContext] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            return nil
        }

        return (item as! SecKey)
    }
}

// MARK: - High-Level Key Protection

/// Combines Secure Enclave and Keychain for defense-in-depth key storage
public final class HardwareBackedKeyStorage {

    private let keychainManager: KeychainManager
    private let secureEnclaveManager: SecureEnclaveManager

    public init(
        keychainManager: KeychainManager = KeychainManager(),
        secureEnclaveManager: SecureEnclaveManager = SecureEnclaveManager()
    ) {
        self.keychainManager = keychainManager
        self.secureEnclaveManager = secureEnclaveManager
    }

    /// Store a PGP key with hardware-backed protection
    ///
    /// Protection layers:
    /// 1. Private key encrypted with user passphrase (OpenPGP S2K)
    /// 2. Encrypted private key wrapped with Secure Enclave KEK
    /// 3. Wrapped key stored in Keychain with ACL protection
    public func storeKey(_ key: PGPKey, requireBiometric: Bool = true) throws {
        guard SecureEnclaveManager.isAvailable else {
            // Fall back to Keychain-only storage
            try keychainManager.storeKey(key, requireBiometric: requireBiometric)
            return
        }

        do {
            // Ensure Secure Enclave KEK exists
            try secureEnclaveManager.ensureKEKExists()

            // For private keys, add Secure Enclave wrapping
            if key.isPrivate, let encryptedPrivKey = key.encryptedPrivateKey {
                let wrappedPrivKey = try secureEnclaveManager.wrap(
                    SecureBytes(data: encryptedPrivKey)
                )

                // Create modified key with wrapped private key data
                var wrappedKey = key
                wrappedKey.encryptedPrivateKey = wrappedPrivKey

                if let encSubkey = key.encryptedEncryptionPrivateKey {
                    wrappedKey.encryptedEncryptionPrivateKey = try secureEnclaveManager.wrap(
                        SecureBytes(data: encSubkey)
                    )
                }

                try keychainManager.storeKey(wrappedKey, requireBiometric: requireBiometric)
            } else {
                // Public key - just store in Keychain
                try keychainManager.storeKey(key, requireBiometric: false)
            }
        } catch {
            // Secure Enclave unavailable (e.g. missing entitlement, no team signing) —
            // fall back to Keychain-only storage
            try keychainManager.storeKey(key, requireBiometric: requireBiometric)
        }
    }

    /// Retrieve a PGP key with hardware-backed unwrapping
    public func retrieveKey(
        keyID: String,
        authContext: LAContext? = nil
    ) throws -> PGPKey {
        var key = try keychainManager.retrieveKey(keyID: keyID)

        guard SecureEnclaveManager.isAvailable else {
            return key
        }

        // For private keys, unwrap using Secure Enclave
        if key.isPrivate, let wrappedPrivKey = key.encryptedPrivateKey {
            let unwrapped = try secureEnclaveManager.unwrap(wrappedPrivKey, authContext: authContext)
            key.encryptedPrivateKey = unwrapped.toData()

            if let wrappedSubkey = key.encryptedEncryptionPrivateKey {
                let unwrappedSubkey = try secureEnclaveManager.unwrap(wrappedSubkey, authContext: authContext)
                key.encryptedEncryptionPrivateKey = unwrappedSubkey.toData()
            }
        }

        return key
    }

    /// List all stored keys
    public func listKeys() throws -> [PGPKey] {
        return try keychainManager.listKeys()
    }

    /// Delete a key
    public func deleteKey(keyID: String) throws {
        try keychainManager.deleteKey(keyID: keyID)
    }
}
