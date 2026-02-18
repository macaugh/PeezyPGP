// EncryptDecryptViews.swift
// PeezyPGP - Privacy-First OpenPGP

import SwiftUI

// MARK: - Encrypt View

struct EncryptView: View {
    @EnvironmentObject var appState: AppState

    @State private var plaintext: String = ""
    @State private var selectedRecipientID: String?
    @State private var encryptedMessage: String = ""
    @State private var error: String?
    @State private var isEncrypting = false

    private var publicKeys: [PGPKey] {
        appState.keys.filter { $0.encryptionPublicKey != nil }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Recipient", selection: $selectedRecipientID) {
                        Text("Select a recipient").tag(nil as String?)
                        ForEach(publicKeys) { key in
                            Text(key.userID).tag(key.id as String?)
                        }
                    }
                } header: {
                    Text("Recipient")
                } footer: {
                    if publicKeys.isEmpty {
                        Text("No keys with encryption capability. Import a recipient's public key first.")
                    }
                }

                Section("Message") {
                    TextEditor(text: $plaintext)
                        .frame(minHeight: 150)

                    if !plaintext.isEmpty {
                        HStack {
                            Text("\(plaintext.count) characters")
                                .font(.caption)
                                .foregroundStyle(.secondary)

                            Spacer()

                            Button("Clear") {
                                plaintext = ""
                            }
                            .font(.caption)
                        }
                    }
                }

                Section {
                    Button(action: encrypt) {
                        HStack {
                            if isEncrypting {
                                ProgressView()
                                    .scaleEffect(0.8)
                            }
                            Text("Encrypt Message")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(plaintext.isEmpty || selectedRecipientID == nil || isEncrypting)
                }

                if !encryptedMessage.isEmpty {
                    Section("Encrypted Message") {
                        Text(encryptedMessage)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)

                        Button(action: copyToClipboard) {
                            Label("Copy to Clipboard", systemImage: "doc.on.doc")
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
            .navigationTitle("Encrypt")
        }
    }

    private func encrypt() {
        guard let recipientID = selectedRecipientID,
              let recipient = appState.keys.first(where: { $0.id == recipientID }) else {
            return
        }

        isEncrypting = true
        error = nil
        encryptedMessage = ""

        Task {
            do {
                let encrypted = try appState.openPGPEngine.encrypt(
                    message: plaintext,
                    recipient: recipient
                )
                await MainActor.run {
                    encryptedMessage = encrypted
                    isEncrypting = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isEncrypting = false
                }
            }
        }
    }

    private func copyToClipboard() {
        #if os(iOS)
        UIPasteboard.general.string = encryptedMessage
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(encryptedMessage, forType: .string)
        #endif
    }
}

// MARK: - Decrypt View

struct DecryptView: View {
    @EnvironmentObject var appState: AppState

    @State private var encryptedMessage: String = ""
    @State private var selectedKeyID: String?
    @State private var passphrase: String = ""
    @State private var decryptedMessage: String = ""
    @State private var error: String?
    @State private var isDecrypting = false
    @State private var showPassphrasePrompt = false

    private var privateKeys: [PGPKey] {
        appState.keys.filter { $0.isPrivate }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Decrypt with", selection: $selectedKeyID) {
                        Text("Select a key").tag(nil as String?)
                        ForEach(privateKeys) { key in
                            Text(key.userID).tag(key.id as String?)
                        }
                    }
                } header: {
                    Text("Private Key")
                } footer: {
                    if privateKeys.isEmpty {
                        Text("No private keys available. Generate a key pair first.")
                    }
                }

                Section("Encrypted Message") {
                    TextEditor(text: $encryptedMessage)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 150)

                    Button(action: pasteFromClipboard) {
                        Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                    }
                }

                Section {
                    Button(action: { showPassphrasePrompt = true }) {
                        HStack {
                            if isDecrypting {
                                ProgressView()
                                    .scaleEffect(0.8)
                            }
                            Text("Decrypt Message")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(encryptedMessage.isEmpty || selectedKeyID == nil || isDecrypting)
                }

                if !decryptedMessage.isEmpty {
                    Section("Decrypted Message") {
                        Text(decryptedMessage)
                            .textSelection(.enabled)

                        Button(action: copyDecrypted) {
                            Label("Copy to Clipboard", systemImage: "doc.on.doc")
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
            .navigationTitle("Decrypt")
            .alert("Enter Passphrase", isPresented: $showPassphrasePrompt) {
                SecureField("Passphrase", text: $passphrase)
                Button("Decrypt") {
                    decrypt()
                }
                Button("Cancel", role: .cancel) {
                    passphrase = ""
                }
            } message: {
                Text("Enter the passphrase for your private key.")
            }
        }
    }

    private func pasteFromClipboard() {
        #if os(iOS)
        if let text = UIPasteboard.general.string {
            encryptedMessage = text
        }
        #else
        if let text = NSPasteboard.general.string(forType: .string) {
            encryptedMessage = text
        }
        #endif
    }

    private func decrypt() {
        guard let keyID = selectedKeyID,
              let privateKey = appState.keys.first(where: { $0.id == keyID }) else {
            return
        }

        isDecrypting = true
        error = nil
        decryptedMessage = ""

        Task {
            do {
                let decrypted = try appState.openPGPEngine.decrypt(
                    armoredMessage: encryptedMessage,
                    privateKey: privateKey,
                    passphrase: passphrase
                )
                await MainActor.run {
                    decryptedMessage = decrypted
                    isDecrypting = false
                    passphrase = ""
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    isDecrypting = false
                    passphrase = ""
                }
            }
        }
    }

    private func copyDecrypted() {
        #if os(iOS)
        UIPasteboard.general.string = decryptedMessage
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(decryptedMessage, forType: .string)
        #endif
    }
}
