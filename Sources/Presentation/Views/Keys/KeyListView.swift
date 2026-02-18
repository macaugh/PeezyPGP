// KeyListView.swift
// PeezyPGP - Privacy-First OpenPGP

import SwiftUI

struct KeyListView: View {
    @EnvironmentObject var appState: AppState
    @State private var showingGenerateSheet = false
    @State private var showingImportSheet = false
    @State private var selectedKey: PGPKey?

    var body: some View {
        NavigationStack {
            Group {
                if appState.keys.isEmpty {
                    EmptyKeysView(
                        onGenerate: { showingGenerateSheet = true },
                        onImport: { showingImportSheet = true }
                    )
                } else {
                    List {
                        Section {
                            ForEach(appState.keys.filter { $0.isPrivate }) { key in
                                KeyRowView(key: key)
                                    .onTapGesture {
                                        selectedKey = key
                                    }
                            }
                            .onDelete(perform: deletePrivateKeys)
                        } header: {
                            Label("My Keys", systemImage: "key.fill")
                        }

                        Section {
                            ForEach(appState.keys.filter { !$0.isPrivate }) { key in
                                KeyRowView(key: key)
                                    .onTapGesture {
                                        selectedKey = key
                                    }
                            }
                            .onDelete(perform: deletePublicKeys)
                        } header: {
                            Label("Contacts", systemImage: "person.2.fill")
                        }
                    }
                }
            }
            .navigationTitle("Keys")
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Menu {
                        Button(action: { showingGenerateSheet = true }) {
                            Label("Generate New Key", systemImage: "plus.circle.fill")
                        }

                        Button(action: { showingImportSheet = true }) {
                            Label("Import Key", systemImage: "square.and.arrow.down")
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingGenerateSheet) {
                KeyGenerationView()
            }
            .sheet(isPresented: $showingImportSheet) {
                KeyImportView()
            }
            .sheet(item: $selectedKey) { key in
                KeyDetailView(key: key)
            }
            .refreshable {
                appState.loadKeys()
            }
        }
    }

    private func deletePrivateKeys(at offsets: IndexSet) {
        let privateKeys = appState.keys.filter { $0.isPrivate }
        for index in offsets {
            let key = privateKeys[index]
            try? appState.deleteKey(keyID: key.id)
        }
    }

    private func deletePublicKeys(at offsets: IndexSet) {
        let publicKeys = appState.keys.filter { !$0.isPrivate }
        for index in offsets {
            let key = publicKeys[index]
            try? appState.deleteKey(keyID: key.id)
        }
    }
}

// MARK: - Empty State

struct EmptyKeysView: View {
    let onGenerate: () -> Void
    let onImport: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "key.slash")
                .font(.system(size: 64))
                .foregroundStyle(.secondary)

            Text("No Keys Yet")
                .font(.title2)
                .fontWeight(.semibold)

            Text("Generate a new key pair or import an existing key to get started.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(spacing: 12) {
                Button(action: onGenerate) {
                    Label("Generate New Key", systemImage: "plus.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button(action: onImport) {
                    Label("Import Key", systemImage: "square.and.arrow.down")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
            .padding(.horizontal, 40)
        }
        .padding()
    }
}

// MARK: - Key Row

struct KeyRowView: View {
    let key: PGPKey

    var body: some View {
        HStack(spacing: 12) {
            // Key icon
            ZStack {
                Circle()
                    .fill(key.isPrivate ? Color.blue.opacity(0.1) : Color.green.opacity(0.1))
                    .frame(width: 44, height: 44)

                Image(systemName: key.isPrivate ? "key.fill" : "person.fill")
                    .foregroundStyle(key.isPrivate ? .blue : .green)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(key.userID)
                    .font(.headline)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(key.shortFingerprint)
                        .font(.caption)
                        .fontDesign(.monospaced)
                        .foregroundStyle(.secondary)

                    if key.isPrivate {
                        Label("Private", systemImage: "lock.fill")
                            .font(.caption2)
                            .foregroundStyle(.blue)
                    }
                }
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

// MARK: - Key Detail View

struct KeyDetailView: View {
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var appState: AppState
    let key: PGPKey

    @State private var showingExportSheet = false
    @State private var showingDeleteAlert = false
    @State private var exportedArmor: String = ""
    @State private var passphrase: String = ""
    @State private var showPassphrasePrompt = false

    var body: some View {
        NavigationStack {
            List {
                Section("Identity") {
                    LabeledContent("User ID", value: key.userID)
                    LabeledContent("Type", value: key.isPrivate ? "Private Key" : "Public Key")
                    LabeledContent("Created", value: key.creationDate.formatted(date: .abbreviated, time: .shortened))
                }

                Section("Fingerprint") {
                    Text(key.fingerprintHex.chunked(by: 4).joined(separator: " "))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }

                Section("Key ID") {
                    Text(key.keyID)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }

                Section("Capabilities") {
                    Label("Sign", systemImage: "signature")
                    if key.encryptionPublicKey != nil {
                        Label("Encrypt", systemImage: "lock.fill")
                    }
                }

                Section {
                    Button(action: { showingExportSheet = true }) {
                        Label("Export Public Key", systemImage: "square.and.arrow.up")
                    }

                    if key.isPrivate {
                        Button(action: { showPassphrasePrompt = true }) {
                            Label("Export Private Key", systemImage: "key.horizontal")
                        }
                    }
                }

                Section {
                    Button(role: .destructive, action: { showingDeleteAlert = true }) {
                        Label("Delete Key", systemImage: "trash")
                    }
                }
            }
            .navigationTitle("Key Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $showingExportSheet) {
                KeyExportView(armor: appState.openPGPEngine.exportPublicKey(key))
            }
            .alert("Enter Passphrase", isPresented: $showPassphrasePrompt) {
                SecureField("Passphrase", text: $passphrase)
                Button("Export") {
                    if let armor = try? appState.openPGPEngine.exportPrivateKey(key, passphrase: passphrase) {
                        exportedArmor = armor
                        showingExportSheet = true
                    }
                }
                Button("Cancel", role: .cancel) { }
            }
            .alert("Delete Key?", isPresented: $showingDeleteAlert) {
                Button("Delete", role: .destructive) {
                    try? appState.deleteKey(keyID: key.id)
                    dismiss()
                }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("This action cannot be undone.")
            }
        }
    }
}

// MARK: - Key Export View

struct KeyExportView: View {
    @Environment(\.dismiss) var dismiss
    let armor: String

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Copy this key to share with others:")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    Text(armor)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)

                    Button(action: {
                        #if os(iOS)
                        UIPasteboard.general.string = armor
                        #else
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(armor, forType: .string)
                        #endif
                    }) {
                        Label("Copy to Clipboard", systemImage: "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
            }
            .navigationTitle("Export Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

// MARK: - String Extension

extension String {
    func chunked(by size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map { i in
            let start = index(startIndex, offsetBy: i)
            let end = index(start, offsetBy: min(size, count - i))
            return String(self[start..<end])
        }
    }
}
