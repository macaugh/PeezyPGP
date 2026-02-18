// KeyGenerationView.swift
// PeezyPGP - Privacy-First OpenPGP

import SwiftUI

struct KeyGenerationView: View {
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var appState: AppState

    @State private var name: String = ""
    @State private var email: String = ""
    @State private var passphrase: String = ""
    @State private var confirmPassphrase: String = ""
    @State private var isGenerating = false
    @State private var error: String?
    @State private var showPassphrase = false

    private var userID: String {
        if email.isEmpty {
            return name
        }
        return "\(name) <\(email)>"
    }

    private var isValid: Bool {
        !name.isEmpty &&
        !passphrase.isEmpty &&
        passphrase == confirmPassphrase &&
        passphrase.count >= 8
    }

    private var passphraseStrength: PassphraseStrength {
        PassphraseStrength.evaluate(passphrase)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name)
                        .textContentType(.name)
                        .autocorrectionDisabled()

                    TextField("Email (optional)", text: $email)
                        .textContentType(.emailAddress)
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()
                } header: {
                    Text("Identity")
                } footer: {
                    Text("This information will be visible to anyone who receives your public key.")
                }

                Section {
                    HStack {
                        Group {
                            if showPassphrase {
                                TextField("Passphrase", text: $passphrase)
                            } else {
                                SecureField("Passphrase", text: $passphrase)
                            }
                        }
                        .textContentType(.newPassword)
                        .autocorrectionDisabled()

                        Button(action: { showPassphrase.toggle() }) {
                            Image(systemName: showPassphrase ? "eye.slash" : "eye")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }

                    if !passphrase.isEmpty {
                        PassphraseStrengthView(strength: passphraseStrength)
                    }

                    SecureField("Confirm Passphrase", text: $confirmPassphrase)
                        .textContentType(.newPassword)

                    if !confirmPassphrase.isEmpty && passphrase != confirmPassphrase {
                        Label("Passphrases do not match", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                } header: {
                    Text("Passphrase")
                } footer: {
                    Text("Your passphrase protects your private key. Use at least 8 characters with a mix of letters, numbers, and symbols.")
                }

                Section {
                    LabeledContent("Algorithm") {
                        Text("Ed25519 + X25519")
                            .foregroundStyle(.secondary)
                    }

                    LabeledContent("Key Version") {
                        Text("OpenPGP v6 (RFC 9580)")
                            .foregroundStyle(.secondary)
                    }

                    LabeledContent("Key Derivation") {
                        Text("Argon2id")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Cryptographic Settings")
                } footer: {
                    Text("PeezyPGP uses modern, secure defaults. These settings provide excellent security.")
                }

                if let error = error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Generate Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Generate") {
                        generateKey()
                    }
                    .disabled(!isValid || isGenerating)
                }
            }
            .interactiveDismissDisabled(isGenerating)
            .overlay {
                if isGenerating {
                    GeneratingOverlay()
                }
            }
        }
    }

    private func generateKey() {
        isGenerating = true
        error = nil

        Task {
            do {
                _ = try await appState.generateKey(userID: userID, passphrase: passphrase)
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    self.isGenerating = false
                }
            }
        }
    }
}

// MARK: - Passphrase Strength

enum PassphraseStrength: Int, Comparable {
    case weak = 0
    case fair = 1
    case good = 2
    case strong = 3

    static func < (lhs: PassphraseStrength, rhs: PassphraseStrength) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .good: return "Good"
        case .strong: return "Strong"
        }
    }

    var color: Color {
        switch self {
        case .weak: return .red
        case .fair: return .orange
        case .good: return .yellow
        case .strong: return .green
        }
    }

    static func evaluate(_ passphrase: String) -> PassphraseStrength {
        var score = 0

        // Length
        if passphrase.count >= 8 { score += 1 }
        if passphrase.count >= 12 { score += 1 }
        if passphrase.count >= 16 { score += 1 }

        // Character variety
        let hasLower = passphrase.contains(where: { $0.isLowercase })
        let hasUpper = passphrase.contains(where: { $0.isUppercase })
        let hasNumber = passphrase.contains(where: { $0.isNumber })
        let hasSymbol = passphrase.contains(where: { !$0.isLetter && !$0.isNumber })

        let variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter { $0 }.count
        score += variety

        // Map score to strength
        switch score {
        case 0...2: return .weak
        case 3...4: return .fair
        case 5...6: return .good
        default: return .strong
        }
    }
}

struct PassphraseStrengthView: View {
    let strength: PassphraseStrength

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<4) { index in
                RoundedRectangle(cornerRadius: 2)
                    .fill(index <= strength.rawValue ? strength.color : Color.gray.opacity(0.3))
                    .frame(height: 4)
            }

            Text(strength.label)
                .font(.caption)
                .foregroundStyle(strength.color)
        }
    }
}

// MARK: - Generating Overlay

struct GeneratingOverlay: View {
    var body: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()

            VStack(spacing: 16) {
                ProgressView()
                    .scaleEffect(1.5)

                Text("Generating Key...")
                    .font(.headline)

                Text("This may take a moment")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(32)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
        }
    }
}

// MARK: - Key Import View

struct KeyImportView: View {
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var appState: AppState

    @State private var armorText: String = ""
    @State private var error: String?
    @State private var isImporting = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Text("Paste an ASCII-armored OpenPGP public key below:")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)

                TextEditor(text: $armorText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 200)
                    .padding(8)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                    .padding(.horizontal)

                if let error = error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.caption)
                        .padding(.horizontal)
                }

                Button(action: pasteFromClipboard) {
                    Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(.bordered)

                Spacer()
            }
            .padding(.top)
            .navigationTitle("Import Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") {
                        importKey()
                    }
                    .disabled(armorText.isEmpty || isImporting)
                }
            }
        }
    }

    private func pasteFromClipboard() {
        #if os(iOS)
        if let text = UIPasteboard.general.string {
            armorText = text
        }
        #else
        if let text = NSPasteboard.general.string(forType: .string) {
            armorText = text
        }
        #endif
    }

    private func importKey() {
        isImporting = true
        error = nil

        do {
            try appState.importKey(armor: armorText)
            dismiss()
        } catch {
            self.error = error.localizedDescription
            isImporting = false
        }
    }
}
