// SignVerifyViews.swift
// PeezyPGP - Privacy-First OpenPGP

import SwiftUI

// MARK: - Sign View

struct SignView: View {
    @EnvironmentObject var appState: AppState

    @State private var message: String = ""
    @State private var selectedKeyID: String?
    @State private var passphrase: String = ""
    @State private var signature: String = ""
    @State private var error: String?
    @State private var isSigning = false
    @State private var showPassphrasePrompt = false

    private var privateKeys: [PGPKey] {
        appState.keys.filter { $0.isPrivate }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Sign with", selection: $selectedKeyID) {
                        Text("Select a key").tag(nil as String?)
                        ForEach(privateKeys) { key in
                            Text(key.userID).tag(key.id as String?)
                        }
                    }
                } header: {
                    Text("Signing Key")
                } footer: {
                    if privateKeys.isEmpty {
                        Text("No private keys available. Generate a key pair first.")
                    }
                }

                Section("Message") {
                    TextEditor(text: $message)
                        .frame(minHeight: 150)

                    if !message.isEmpty {
                        HStack {
                            Text("\(message.count) characters")
                                .font(.caption)
                                .foregroundStyle(.secondary)

                            Spacer()

                            Button("Clear") {
                                message = ""
                            }
                            .font(.caption)
                        }
                    }
                }

                Section {
                    Button(action: { showPassphrasePrompt = true }) {
                        HStack {
                            if isSigning {
                                ProgressView()
                                    .scaleEffect(0.8)
                            }
                            Text("Sign Message")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(message.isEmpty || selectedKeyID == nil || isSigning)
                }

                if !signature.isEmpty {
                    Section("Detached Signature") {
                        Text(signature)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)

                        Button(action: copySignature) {
                            Label("Copy Signature", systemImage: "doc.on.doc")
                        }

                        Button(action: copyAll) {
                            Label("Copy Message + Signature", systemImage: "doc.on.doc.fill")
                        }
                    }
                }

                if let error = error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Sign")
            .alert("Enter Passphrase", isPresented: $showPassphrasePrompt) {
                SecureField("Passphrase", text: $passphrase)
                Button("Sign") {
                    sign()
                }
                Button("Cancel", role: .cancel) {
                    passphrase = ""
                }
            } message: {
                Text("Enter the passphrase for your private key.")
            }
        }
    }

    private func sign() {
        guard let keyID = selectedKeyID,
              let privateKey = appState.keys.first(where: { $0.id == keyID }) else {
            return
        }

        isSigning = true
        error = nil
        signature = ""

        Task {
            do {
                let sig = try appState.openPGPEngine.sign(
                    message: message,
                    privateKey: privateKey,
                    passphrase: passphrase
                )
                await MainActor.run {
                    signature = sig
                    isSigning = false
                    passphrase = ""
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isSigning = false
                    passphrase = ""
                }
            }
        }
    }

    private func copySignature() {
        #if os(iOS)
        UIPasteboard.general.string = signature
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(signature, forType: .string)
        #endif
    }

    private func copyAll() {
        let combined = """
        \(message)

        \(signature)
        """
        #if os(iOS)
        UIPasteboard.general.string = combined
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(combined, forType: .string)
        #endif
    }
}

// MARK: - Verify View

struct VerifyView: View {
    @EnvironmentObject var appState: AppState

    @State private var message: String = ""
    @State private var signature: String = ""
    @State private var selectedKeyID: String?
    @State private var verificationResult: VerificationResult?
    @State private var error: String?
    @State private var isVerifying = false

    private var publicKeys: [PGPKey] {
        appState.keys
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Verify with", selection: $selectedKeyID) {
                        Text("Select a key").tag(nil as String?)
                        ForEach(publicKeys) { key in
                            Text(key.userID).tag(key.id as String?)
                        }
                    }
                } header: {
                    Text("Signer's Key")
                } footer: {
                    if publicKeys.isEmpty {
                        Text("No keys available. Import the signer's public key first.")
                    }
                }

                Section("Message") {
                    TextEditor(text: $message)
                        .frame(minHeight: 100)

                    Button(action: pasteMessage) {
                        Label("Paste Message", systemImage: "doc.on.clipboard")
                    }
                }

                Section("Signature") {
                    TextEditor(text: $signature)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 100)

                    Button(action: pasteSignature) {
                        Label("Paste Signature", systemImage: "doc.on.clipboard")
                    }
                }

                Section {
                    Button(action: verify) {
                        HStack {
                            if isVerifying {
                                ProgressView()
                                    .scaleEffect(0.8)
                            }
                            Text("Verify Signature")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(message.isEmpty || signature.isEmpty || selectedKeyID == nil || isVerifying)
                }

                if let result = verificationResult {
                    Section("Result") {
                        HStack {
                            Image(systemName: result.isValid ? "checkmark.seal.fill" : "xmark.seal.fill")
                                .font(.title)
                                .foregroundStyle(result.isValid ? .green : .red)

                            VStack(alignment: .leading) {
                                Text(result.isValid ? "Valid Signature" : "Invalid Signature")
                                    .font(.headline)
                                    .foregroundStyle(result.isValid ? .green : .red)

                                if result.isValid {
                                    Text("The message was signed by this key and has not been modified.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                } else {
                                    Text("The signature does not match. The message may have been tampered with.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 8)
                    }
                }

                if let error = error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Verify")
        }
    }

    private func pasteMessage() {
        #if os(iOS)
        if let text = UIPasteboard.general.string {
            message = text
        }
        #else
        if let text = NSPasteboard.general.string(forType: .string) {
            message = text
        }
        #endif
    }

    private func pasteSignature() {
        #if os(iOS)
        if let text = UIPasteboard.general.string {
            signature = text
        }
        #else
        if let text = NSPasteboard.general.string(forType: .string) {
            signature = text
        }
        #endif
    }

    private func verify() {
        guard let keyID = selectedKeyID,
              let publicKey = appState.keys.first(where: { $0.id == keyID }) else {
            return
        }

        isVerifying = true
        error = nil
        verificationResult = nil

        Task {
            do {
                let isValid = try appState.openPGPEngine.verify(
                    message: message,
                    signature: signature,
                    publicKey: publicKey
                )
                await MainActor.run {
                    verificationResult = VerificationResult(isValid: isValid, signerKey: publicKey)
                    isVerifying = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isVerifying = false
                }
            }
        }
    }
}

// MARK: - Verification Result

struct VerificationResult {
    let isValid: Bool
    let signerKey: PGPKey
}
