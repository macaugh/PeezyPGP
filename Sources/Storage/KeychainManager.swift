// KeychainManager.swift
// PeezyPGP - Privacy-First OpenPGP
//
// Secure storage for PGP keys using Apple Keychain
// Implements defense-in-depth with multiple protection layers

import Foundation
import Security
import LocalAuthentication

// MARK: - Keychain Error

/// Errors specific to Keychain operations
public enum KeychainError: Error, LocalizedError {
    case itemNotFound
    case duplicateItem
    case authenticationFailed
    case accessDenied
    case unexpectedData
    case unhandledError(OSStatus)
    case biometricNotAvailable
    case biometricNotEnrolled
    case biometricLockout

    public var errorDescription: String? {
        switch self {
        case .itemNotFound:
            return "Item not found in Keychain"
        case .duplicateItem:
            return "Item already exists in Keychain"
        case .authenticationFailed:
            return "Authentication failed"
        case .accessDenied:
            return "Access denied to Keychain item"
        case .unexpectedData:
            return "Unexpected data format in Keychain"
        case .unhandledError(let status):
            return "Keychain error: \(status)"
        case .biometricNotAvailable:
            return "Biometric authentication not available"
        case .biometricNotEnrolled:
            return "No biometric data enrolled"
        case .biometricLockout:
            return "Biometric authentication locked out"
        }
    }
}

// MARK: - Keychain Protection Level

/// Protection level for Keychain items
public enum KeychainProtection {
    /// Accessible only when device is unlocked
    case whenUnlocked

    /// Accessible only when device is unlocked, not included in backups
    case whenUnlockedThisDeviceOnly

    /// Accessible only after first unlock (survives reboot)
    case afterFirstUnlock

    /// Accessible only after first unlock, not included in backups
    case afterFirstUnlockThisDeviceOnly

    /// Requires biometric or passcode each time
    case biometricCurrentSet

    /// Requires biometric or passcode, not in backups
    case biometricCurrentSetThisDeviceOnly

    var secAccessibleValue: CFString {
        switch self {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .biometricCurrentSet:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .biometricCurrentSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
}

// MARK: - Keychain Manager

/// Manages secure storage of PGP keys in Apple Keychain
public final class KeychainManager {

    // MARK: - Properties

    /// Service name for Keychain items
    private let serviceName: String

    /// Access group for shared Keychain access (nil for app-only)
    private let accessGroup: String?

    /// Default protection level
    private let defaultProtection: KeychainProtection

    // MARK: - Initialization

    public init(
        serviceName: String = "com.peezypgp.keys",
        accessGroup: String? = nil,
        defaultProtection: KeychainProtection = .whenUnlockedThisDeviceOnly
    ) {
        self.serviceName = serviceName
        self.accessGroup = accessGroup
        self.defaultProtection = defaultProtection
    }

    // MARK: - Key Storage

    /// Store a PGP key in the Keychain
    /// - Parameters:
    ///   - key: The PGP key to store
    ///   - requireBiometric: Whether to require biometric authentication for access
    public func storeKey(_ key: PGPKey, requireBiometric: Bool = false) throws {
        let encoder = JSONEncoder()
        let keyData = try encoder.encode(key)

        // Build query
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: key.id,
            kSecValueData: keyData,
            kSecAttrLabel: "PeezyPGP Key: \(key.userID)",
            kSecAttrDescription: key.isPrivate ? "Private Key" : "Public Key"
        ]

        // Add access group if specified
        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        // Configure access control
        if requireBiometric {
            var error: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryCurrentSet, .privateKeyUsage],
                &error
            ) else {
                throw KeychainError.unhandledError(-1)
            }
            query[kSecAttrAccessControl] = accessControl
        } else {
            query[kSecAttrAccessible] = defaultProtection.secAccessibleValue
        }

        // Delete existing item if present
        let deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: key.id
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw mapSecurityError(status)
        }
    }

    /// Retrieve a PGP key from the Keychain
    /// - Parameters:
    ///   - keyID: The key ID to retrieve
    ///   - promptMessage: Optional message to display during biometric prompt
    /// - Returns: The retrieved PGP key
    public func retrieveKey(
        keyID: String,
        promptMessage: String? = nil
    ) throws -> PGPKey {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: keyID,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]

        // Add access group if specified
        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        // Add authentication context if prompt message provided
        if let message = promptMessage {
            let context = LAContext()
            context.localizedReason = message
            query[kSecUseAuthenticationContext] = context
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw mapSecurityError(status)
        }

        guard let keyData = result as? Data else {
            throw KeychainError.unexpectedData
        }

        let decoder = JSONDecoder()
        return try decoder.decode(PGPKey.self, from: keyData)
    }

    /// List all stored key IDs
    /// - Returns: Array of key IDs
    public func listKeyIDs() throws -> [String] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitAll
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return []
        }

        guard status == errSecSuccess else {
            throw mapSecurityError(status)
        }

        guard let items = result as? [[CFString: Any]] else {
            throw KeychainError.unexpectedData
        }

        return items.compactMap { $0[kSecAttrAccount] as? String }
    }

    /// List all stored keys (metadata only, doesn't decrypt private data)
    public func listKeys() throws -> [PGPKey] {
        let keyIDs = try listKeyIDs()
        return keyIDs.compactMap { try? retrieveKey(keyID: $0) }
    }

    /// Delete a key from the Keychain
    /// - Parameter keyID: The key ID to delete
    public func deleteKey(keyID: String) throws {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: keyID
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapSecurityError(status)
        }
    }

    /// Delete all keys from the Keychain
    public func deleteAllKeys() throws {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapSecurityError(status)
        }
    }

    /// Check if a key exists
    /// - Parameter keyID: The key ID to check
    /// - Returns: true if the key exists
    public func keyExists(keyID: String) -> Bool {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: keyID,
            kSecReturnData: false
        ]

        if let group = accessGroup {
            query[kSecAttrAccessGroup] = group
        }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    // MARK: - Private Helpers

    private func mapSecurityError(_ status: OSStatus) -> KeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        case errSecDuplicateItem:
            return .duplicateItem
        case errSecAuthFailed:
            return .authenticationFailed
        case errSecInteractionNotAllowed:
            return .accessDenied
        default:
            return .unhandledError(status)
        }
    }
}

// MARK: - Biometric Authentication Helper

/// Helper for biometric authentication
public final class BiometricAuthenticator {

    /// Check if biometric authentication is available
    public static func isBiometricAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Get the type of biometric available
    public static func biometricType() -> LABiometryType {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        return context.biometryType
    }

    /// Authenticate using biometrics
    /// - Parameters:
    ///   - reason: Reason to display to user
    ///   - completion: Completion handler with success/failure
    public static func authenticate(
        reason: String,
        completion: @escaping (Result<Void, KeychainError>) -> Void
    ) {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            if let error = error {
                switch error.code {
                case LAError.biometryNotAvailable.rawValue:
                    completion(.failure(.biometricNotAvailable))
                case LAError.biometryNotEnrolled.rawValue:
                    completion(.failure(.biometricNotEnrolled))
                case LAError.biometryLockout.rawValue:
                    completion(.failure(.biometricLockout))
                default:
                    completion(.failure(.authenticationFailed))
                }
            } else {
                completion(.failure(.biometricNotAvailable))
            }
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { success, error in
            DispatchQueue.main.async {
                if success {
                    completion(.success(()))
                } else if let error = error as? LAError {
                    switch error.code {
                    case .authenticationFailed:
                        completion(.failure(.authenticationFailed))
                    case .userCancel, .userFallback:
                        completion(.failure(.authenticationFailed))
                    case .biometryLockout:
                        completion(.failure(.biometricLockout))
                    default:
                        completion(.failure(.authenticationFailed))
                    }
                } else {
                    completion(.failure(.authenticationFailed))
                }
            }
        }
    }

    /// Authenticate using biometrics (async)
    @available(iOS 15.0, macOS 12.0, *)
    public static func authenticate(reason: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            authenticate(reason: reason) { result in
                switch result {
                case .success:
                    continuation.resume()
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
