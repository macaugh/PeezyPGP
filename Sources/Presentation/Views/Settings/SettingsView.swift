// SettingsView.swift
// PeezyPGP - Privacy-First OpenPGP

import SwiftUI
import LocalAuthentication

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @AppStorage("requireBiometric") private var requireBiometric = true
    @AppStorage("autoClearClipboard") private var autoClearClipboard = true
    @AppStorage("clipboardClearDelay") private var clipboardClearDelay = 60

    @State private var showingDeleteAllAlert = false
    @State private var biometricType: LABiometryType = .none

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(isOn: $requireBiometric) {
                        Label {
                            VStack(alignment: .leading) {
                                Text("Require \(biometricName)")
                                Text("Authenticate before accessing private keys")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: biometricIcon)
                        }
                    }
                    .disabled(!BiometricAuthenticator.isBiometricAvailable())
                } header: {
                    Text("Security")
                }

                Section {
                    Toggle(isOn: $autoClearClipboard) {
                        Label {
                            VStack(alignment: .leading) {
                                Text("Auto-Clear Clipboard")
                                Text("Clear sensitive data after copying")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: "doc.on.clipboard")
                        }
                    }

                    if autoClearClipboard {
                        Stepper(value: $clipboardClearDelay, in: 15...300, step: 15) {
                            Label {
                                Text("Clear after \(clipboardClearDelay) seconds")
                            } icon: {
                                Image(systemName: "timer")
                            }
                        }
                    }
                } header: {
                    Text("Clipboard")
                }

                Section {
                    LabeledContent("Secure Enclave") {
                        Text(SecureEnclaveManager.isAvailable ? "Available" : "Not Available")
                            .foregroundStyle(SecureEnclaveManager.isAvailable ? .green : .secondary)
                    }

                    LabeledContent("Biometric") {
                        Text(biometricName)
                            .foregroundStyle(BiometricAuthenticator.isBiometricAvailable() ? .green : .secondary)
                    }

                    LabeledContent("Keys Stored") {
                        Text("\(appState.keys.count)")
                    }
                } header: {
                    Text("System Info")
                }

                Section {
                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("About PeezyPGP", systemImage: "info.circle")
                    }

                    NavigationLink {
                        PrivacyPolicyView()
                    } label: {
                        Label("Privacy Policy", systemImage: "hand.raised.fill")
                    }
                } header: {
                    Text("Info")
                }

                Section {
                    Button(role: .destructive, action: { showingDeleteAllAlert = true }) {
                        Label("Delete All Keys", systemImage: "trash.fill")
                            .foregroundStyle(.red)
                    }
                } header: {
                    Text("Danger Zone")
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                biometricType = BiometricAuthenticator.biometricType()
            }
            .alert("Delete All Keys?", isPresented: $showingDeleteAllAlert) {
                Button("Delete All", role: .destructive) {
                    try? appState.keychainManager.deleteAllKeys()
                    appState.loadKeys()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("This will permanently delete all stored keys. This action cannot be undone.")
            }
        }
    }

    private var biometricName: String {
        switch biometricType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "Biometric"
        }
    }

    private var biometricIcon: String {
        switch biometricType {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        default: return "lock.fill"
        }
    }
}

// MARK: - About View

struct AboutView: View {
    var body: some View {
        List {
            Section {
                VStack(spacing: 16) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 64))
                        .foregroundStyle(.blue)

                    Text("PeezyPGP")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Privacy-First OpenPGP")
                        .font(.headline)
                        .foregroundStyle(.secondary)

                    Text("Version 1.0.0")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 24)
            }

            Section("Features") {
                FeatureRow(icon: "key.fill", title: "OpenPGP Keys", description: "Generate Ed25519 + X25519 key pairs")
                FeatureRow(icon: "lock.fill", title: "Encryption", description: "AES-256-GCM with ECDH key agreement")
                FeatureRow(icon: "signature", title: "Signatures", description: "Ed25519 digital signatures")
                FeatureRow(icon: "cpu.fill", title: "Secure Enclave", description: "Hardware-backed key protection")
                FeatureRow(icon: "wifi.slash", title: "Offline Only", description: "Zero network access")
            }

            Section("Cryptographic Standards") {
                LabeledContent("OpenPGP", value: "RFC 9580")
                LabeledContent("Signing", value: "Ed25519")
                LabeledContent("Key Agreement", value: "X25519")
                LabeledContent("Symmetric", value: "AES-256-GCM")
                LabeledContent("Hash", value: "SHA-256/512")
                LabeledContent("KDF", value: "Argon2id")
            }

            Section {
                Text("PeezyPGP is designed for high-assurance cryptography with security as the primary goal. No data ever leaves your device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct FeatureRow: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(width: 32)

            VStack(alignment: .leading) {
                Text(title)
                    .font(.headline)
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Privacy Policy View

struct PrivacyPolicyView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Group {
                    Text("Privacy Policy")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Effective: January 2025")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                PolicySection(
                    title: "Data Collection",
                    content: "PeezyPGP collects no data whatsoever. The app operates entirely offline with zero network capabilities."
                )

                PolicySection(
                    title: "Network Access",
                    content: "PeezyPGP has no network permissions. It cannot connect to the internet, send telemetry, or communicate with any servers."
                )

                PolicySection(
                    title: "Analytics",
                    content: "There are no analytics, crash reporting, or usage tracking of any kind."
                )

                PolicySection(
                    title: "Key Storage",
                    content: "Your cryptographic keys are stored exclusively in the Apple Keychain on your device, protected by the Secure Enclave when available. Keys never leave your device."
                )

                PolicySection(
                    title: "Clipboard",
                    content: "When you copy sensitive data, it remains on your device's clipboard. Enable auto-clear in settings to automatically remove it after a set period."
                )

                PolicySection(
                    title: "Backups",
                    content: "Private keys are stored with 'This Device Only' protection, meaning they are excluded from iCloud backups."
                )

                Text("Your privacy is not just a feature — it's the foundation of PeezyPGP.")
                    .font(.headline)
                    .padding(.top)
            }
            .padding()
        }
        .navigationTitle("Privacy")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct PolicySection: View {
    let title: String
    let content: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)

            Text(content)
                .font(.body)
                .foregroundStyle(.secondary)
        }
    }
}
