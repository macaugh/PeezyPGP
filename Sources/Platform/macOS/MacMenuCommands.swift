// MacMenuCommands.swift
// PeezyPGP - Privacy-First OpenPGP
//
// macOS-specific menu bar commands and keyboard shortcuts

import SwiftUI

#if os(macOS)
struct PeezyPGPCommands: Commands {
    @FocusedValue(\.selectedKey) var selectedKey

    var body: some Commands {
        // Replace default New menu
        CommandGroup(replacing: .newItem) {
            Button("Generate New Key...") {
                NotificationCenter.default.post(name: .generateNewKey, object: nil)
            }
            .keyboardShortcut("n", modifiers: [.command])

            Button("Import Key...") {
                NotificationCenter.default.post(name: .importKey, object: nil)
            }
            .keyboardShortcut("i", modifiers: [.command])
        }

        // File operations
        CommandGroup(after: .newItem) {
            Divider()

            Button("Export Public Key...") {
                NotificationCenter.default.post(name: .exportPublicKey, object: selectedKey)
            }
            .keyboardShortcut("e", modifiers: [.command])
            .disabled(selectedKey == nil)

            Button("Export Private Key...") {
                NotificationCenter.default.post(name: .exportPrivateKey, object: selectedKey)
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])
            .disabled(selectedKey == nil || selectedKey?.isPrivate != true)
        }

        // Encryption commands
        CommandMenu("Crypto") {
            Button("Encrypt Message...") {
                NotificationCenter.default.post(name: .encryptMessage, object: nil)
            }
            .keyboardShortcut("e", modifiers: [.command, .option])

            Button("Decrypt Message...") {
                NotificationCenter.default.post(name: .decryptMessage, object: nil)
            }
            .keyboardShortcut("d", modifiers: [.command, .option])

            Divider()

            Button("Sign Message...") {
                NotificationCenter.default.post(name: .signMessage, object: nil)
            }
            .keyboardShortcut("s", modifiers: [.command, .option])

            Button("Verify Signature...") {
                NotificationCenter.default.post(name: .verifySignature, object: nil)
            }
            .keyboardShortcut("v", modifiers: [.command, .option])
        }

        // Security menu
        CommandMenu("Security") {
            Button("Lock App") {
                NotificationCenter.default.post(name: .lockApp, object: nil)
            }
            .keyboardShortcut("l", modifiers: [.command, .control])

            Divider()

            Button("Clear Clipboard") {
                NSPasteboard.general.clearContents()
            }
            .keyboardShortcut("k", modifiers: [.command, .shift])
        }

        // Help menu additions
        CommandGroup(replacing: .help) {
            Button("PeezyPGP Help") {
                // Open help
            }

            Divider()

            Button("Keyboard Shortcuts") {
                NotificationCenter.default.post(name: .showKeyboardShortcuts, object: nil)
            }
            .keyboardShortcut("/", modifiers: [.command])

            Button("About PeezyPGP") {
                NotificationCenter.default.post(name: .showAbout, object: nil)
            }
        }
    }
}

// MARK: - Notification Names

extension Notification.Name {
    static let generateNewKey = Notification.Name("generateNewKey")
    static let importKey = Notification.Name("importKey")
    static let exportPublicKey = Notification.Name("exportPublicKey")
    static let exportPrivateKey = Notification.Name("exportPrivateKey")
    static let encryptMessage = Notification.Name("encryptMessage")
    static let decryptMessage = Notification.Name("decryptMessage")
    static let signMessage = Notification.Name("signMessage")
    static let verifySignature = Notification.Name("verifySignature")
    static let lockApp = Notification.Name("lockApp")
    static let showKeyboardShortcuts = Notification.Name("showKeyboardShortcuts")
    static let showAbout = Notification.Name("showAbout")
}

// MARK: - Focused Value for Selected Key

struct SelectedKeyKey: FocusedValueKey {
    typealias Value = PGPKey
}

extension FocusedValues {
    var selectedKey: PGPKey? {
        get { self[SelectedKeyKey.self] }
        set { self[SelectedKeyKey.self] = newValue }
    }
}

// MARK: - macOS Window Configuration

extension View {
    func macOSWindowConfiguration() -> some View {
        self
            .frame(minWidth: 800, minHeight: 600)
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                // Clear clipboard on app termination for security
                NSPasteboard.general.clearContents()
            }
    }
}

// MARK: - macOS Toolbar

struct MacToolbar: ToolbarContent {
    @Binding var selectedTab: Int

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            Button(action: { selectedTab = 0 }) {
                Label("Keys", systemImage: "key.fill")
            }
            .help("Manage Keys")

            Button(action: { selectedTab = 1 }) {
                Label("Encrypt", systemImage: "lock.fill")
            }
            .help("Encrypt Message")

            Button(action: { selectedTab = 2 }) {
                Label("Decrypt", systemImage: "lock.open.fill")
            }
            .help("Decrypt Message")

            Button(action: { selectedTab = 3 }) {
                Label("Sign", systemImage: "signature")
            }
            .help("Sign Message")
        }
    }
}

// MARK: - Keyboard Shortcuts View

struct KeyboardShortcutsView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Keyboard Shortcuts")
                .font(.largeTitle)
                .fontWeight(.bold)

            Grid(alignment: .leading, horizontalSpacing: 40, verticalSpacing: 12) {
                GridRow {
                    Text("Keys")
                        .font(.headline)
                        .gridCellColumns(2)
                }

                ShortcutRow(key: "⌘N", description: "Generate New Key")
                ShortcutRow(key: "⌘I", description: "Import Key")
                ShortcutRow(key: "⌘E", description: "Export Public Key")
                ShortcutRow(key: "⇧⌘E", description: "Export Private Key")

                GridRow {
                    Text("Crypto")
                        .font(.headline)
                        .gridCellColumns(2)
                        .padding(.top)
                }

                ShortcutRow(key: "⌥⌘E", description: "Encrypt Message")
                ShortcutRow(key: "⌥⌘D", description: "Decrypt Message")
                ShortcutRow(key: "⌥⌘S", description: "Sign Message")
                ShortcutRow(key: "⌥⌘V", description: "Verify Signature")

                GridRow {
                    Text("Security")
                        .font(.headline)
                        .gridCellColumns(2)
                        .padding(.top)
                }

                ShortcutRow(key: "⌃⌘L", description: "Lock App")
                ShortcutRow(key: "⇧⌘K", description: "Clear Clipboard")
            }
        }
        .padding(40)
        .frame(width: 400)
    }
}

struct ShortcutRow: View {
    let key: String
    let description: String

    var body: some View {
        GridRow {
            Text(key)
                .font(.system(.body, design: .monospaced))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.gray.opacity(0.2))
                .cornerRadius(4)

            Text(description)
                .foregroundStyle(.secondary)
        }
    }
}
#endif
