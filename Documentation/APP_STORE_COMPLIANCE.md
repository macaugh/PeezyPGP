# PeezyPGP App Store Compliance Guide

## Export Compliance (Encryption)

### ECCN Classification

PeezyPGP uses strong cryptography and requires export compliance documentation:

**Algorithms Used:**
- AES-256-GCM (symmetric encryption)
- Ed25519 (digital signatures)
- X25519 (key agreement)
- SHA-256/SHA-512 (hashing)
- Argon2id (key derivation)

**Classification:**
- ECCN: 5D002 (Information Security Software)
- License Exception: TSU (Technology and Software Unrestricted)

### App Store Connect Declarations

When submitting to App Store Connect, answer the export compliance questions as follows:

1. **"Does your app use encryption?"** → YES

2. **"Does your app qualify for any exemptions?"**
   - Select: "My app uses encryption but qualifies for an exemption"
   - Reason: The app uses standard encryption for authentication/data protection

3. **If required, provide:**
   - CCATS classification document (if you have one)
   - Or self-classify under TSU exception

### Annual Self-Classification Report

File BIS annual self-classification report by February 1st each year:
- Website: https://www.bis.doc.gov/index.php/policy-guidance/encryption

---

## Privacy Requirements

### App Privacy Labels (App Store Connect)

Configure the following privacy nutrition labels:

**Data Not Collected:**
- PeezyPGP collects NO data whatsoever
- Select "Data Not Collected" for all categories

**Data Not Linked to You:**
- N/A (no data collected)

**Data Used to Track You:**
- N/A (no tracking capabilities)

### Privacy Policy Requirements

A privacy policy URL is required. Host a simple page stating:

> PeezyPGP collects no data. The app operates entirely offline with zero network access. Your cryptographic keys are stored exclusively on your device.

---

## App Review Guidelines Compliance

### 2.1 App Completeness
- ✅ All features are fully functional
- ✅ No placeholder content
- ✅ No debug builds

### 2.3 Accurate Metadata
- ✅ App description accurately reflects functionality
- ✅ Screenshots show actual app screens
- ✅ No misleading claims

### 2.5 Software Requirements
- ✅ Uses only public APIs
- ✅ No private framework access
- ✅ No deprecated API usage

### 4.2 Minimum Functionality
- ✅ App provides clear utility (OpenPGP encryption)
- ✅ Not a simple website wrapper
- ✅ Unique value proposition

### 5.1 Privacy

**5.1.1 Data Collection and Storage:**
- ✅ No data collection
- ✅ Keys stored only in Keychain
- ✅ No cloud sync

**5.1.2 Data Use and Sharing:**
- ✅ No data sharing (impossible without network)
- ✅ No third-party analytics

---

## Required Capabilities

### iOS Capabilities
```
- Keychain Sharing (optional, for app groups)
- Data Protection: Complete
```

### macOS Capabilities
```
- App Sandbox: Enabled
- Hardened Runtime: Enabled
- Keychain Access
- File Access: User Selected (Read-Write)
```

---

## Testing Checklist for Submission

### Functional Testing
- [ ] Key generation works
- [ ] Key import/export works
- [ ] Encryption/decryption round-trip successful
- [ ] Signing/verification round-trip successful
- [ ] Biometric authentication works
- [ ] All error states handled gracefully

### Security Testing
- [ ] No network requests (verify with proxy)
- [ ] Keys stored in Keychain (verify with Keychain Access)
- [ ] Sensitive data zeroed after use
- [ ] Clipboard cleared appropriately

### UI/UX Testing
- [ ] Dark mode works
- [ ] Light mode works
- [ ] Dynamic Type supported
- [ ] VoiceOver accessible
- [ ] All orientations work (iPad)
- [ ] Mac Catalyst works (if applicable)

### Device Testing
- [ ] iPhone (various sizes)
- [ ] iPad
- [ ] Mac (Apple Silicon)
- [ ] Mac (Intel) if supporting

---

## Rejection Risk Mitigation

### Common Rejection Reasons and Mitigations

1. **Guideline 2.1 - App Completeness**
   - Ensure all UI elements are functional
   - Remove any "Coming Soon" features

2. **Guideline 4.2 - Minimum Functionality**
   - App provides genuine utility
   - Not just a thin wrapper

3. **Guideline 5.1.1 - Data Collection**
   - Privacy policy must be accurate
   - App Privacy labels must match behavior

### Review Notes to Include

Include in "Notes for Reviewer":

```
PeezyPGP is a privacy-focused OpenPGP encryption app. Key features:

1. OFFLINE ONLY: This app has zero network capabilities. It cannot connect to the internet.

2. NO DATA COLLECTION: No analytics, telemetry, or user data collection of any kind.

3. CRYPTOGRAPHY: Uses Apple CryptoKit for all cryptographic operations:
   - Ed25519 for signing
   - X25519 for key agreement
   - AES-256-GCM for encryption
   - Argon2id for key derivation

4. KEY STORAGE: All keys stored in Apple Keychain with Secure Enclave protection when available.

To test:
1. Generate a key pair (requires passphrase)
2. Export and reimport the public key
3. Encrypt a message to yourself
4. Decrypt using your private key

No account or network connection is needed.
```

---

## Version Update Guidelines

When updating the app:

1. **Version Numbering:**
   - Major.Minor.Patch (e.g., 1.2.3)
   - Increment patch for bug fixes
   - Increment minor for new features
   - Increment major for breaking changes

2. **What's New:**
   - Clear, concise changelog
   - Focus on user-facing changes
   - Note any security improvements

3. **Re-verification:**
   - Re-test all security properties
   - Verify no new network calls
   - Confirm Keychain behavior unchanged
