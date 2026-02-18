// PeezyPGPApp.swift
// PeezyPGP - Privacy-First OpenPGP
//
// App entry point for iOS and macOS

import SwiftUI

@main
struct PeezyPGPApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
        #if os(macOS)
        .commands {
            // Custom menu commands for macOS
            PeezyPGPCommands()
        }
        #endif

        #if os(macOS)
        Settings {
            SettingsView()
                .environmentObject(appState)
        }
        #endif
    }
}

// MARK: - App State

/// Global application state
@MainActor
final class AppState: ObservableObject {
    @Published var keys: [PGPKey] = []
    @Published var selectedKeyID: String?
    @Published var isLoading = false
    @Published var errorMessage: String?

    let keychainManager = KeychainManager()
    let openPGPEngine = OpenPGPEngine()
    let hardwareStorage: HardwareBackedKeyStorage

    init() {
        self.hardwareStorage = HardwareBackedKeyStorage(keychainManager: keychainManager)
        loadKeys()
    }

    func loadKeys() {
        isLoading = true
        defer { isLoading = false }

        do {
            keys = try keychainManager.listKeys()
        } catch {
            errorMessage = "Failed to load keys: \(error.localizedDescription)"
        }
    }

    func generateKey(userID: String, passphrase: String) async throws -> PGPKey {
        let params = KeyGenerationParameters(
            userID: userID,
            passphrase: passphrase
        )

        let key = try openPGPEngine.generateKeyPair(params: params)

        // Store with hardware backing if available
        try hardwareStorage.storeKey(key, requireBiometric: false)

        await MainActor.run {
            keys.append(key)
        }

        return key
    }

    func deleteKey(keyID: String) throws {
        try hardwareStorage.deleteKey(keyID: keyID)
        keys.removeAll { $0.id == keyID }
    }

    func importKey(armor: String) throws {
        let key = try openPGPEngine.importPublicKey(armor)
        try hardwareStorage.storeKey(key, requireBiometric: false)
        keys.append(key)
    }
}

// MARK: - Content View

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0

    var body: some View {
        #if os(iOS)
        TabView(selection: $selectedTab) {
            KeyListView()
                .tabItem {
                    Label("Keys", systemImage: "key.fill")
                }
                .tag(0)

            EncryptView()
                .tabItem {
                    Label("Encrypt", systemImage: "lock.fill")
                }
                .tag(1)

            DecryptView()
                .tabItem {
                    Label("Decrypt", systemImage: "lock.open.fill")
                }
                .tag(2)

            SignView()
                .tabItem {
                    Label("Sign", systemImage: "signature")
                }
                .tag(3)

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
                .tag(4)
        }
        #else
        NavigationSplitView {
            SidebarView(selectedTab: $selectedTab)
        } detail: {
            switch selectedTab {
            case 0:
                KeyListView()
            case 1:
                EncryptView()
            case 2:
                DecryptView()
            case 3:
                SignView()
            default:
                KeyListView()
            }
        }
        .frame(minWidth: 800, minHeight: 600)
        #endif
    }
}

// MARK: - macOS Sidebar

#if os(macOS)
struct SidebarView: View {
    @Binding var selectedTab: Int

    var body: some View {
        List(selection: $selectedTab) {
            Label("Keys", systemImage: "key.fill")
                .tag(0)

            Section("Operations") {
                Label("Encrypt", systemImage: "lock.fill")
                    .tag(1)

                Label("Decrypt", systemImage: "lock.open.fill")
                    .tag(2)

                Label("Sign", systemImage: "signature")
                    .tag(3)

                Label("Verify", systemImage: "checkmark.seal.fill")
                    .tag(4)
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("PeezyPGP")
    }
}
#endif
