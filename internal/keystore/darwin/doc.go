// Package darwin implements keystore.KeyStore on macOS using Security.framework.
//
// # Modes
//
// Primary ("secure-enclave", presence.TierHardware): a P-256 key created in the
// Secure Enclave (SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave,
// permanent, application tag "dev.grantd.vault-kek"). Wrap is ECIES
// (kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM) to the
// public key; Unwrap is the matching private-key operation performed inside the
// Secure Enclave. The private key can never be exported.
//
// Opt-in fallback ("keychain-fallback", presence.TierDialog): when the Secure
// Enclave is unusable (VMs, no SE, unsigned binary without keychain
// entitlements) AND WithAllowKeychainFallback(true) was given, a random 32-byte
// KEK is stored as a generic-password Keychain item (service "dev.grantd",
// account "vault-kek") and the data key is wrapped with AES-256-GCM in Go. The
// default refuses to fall back and returns ErrSecureEnclaveUnavailable.
//
// # DECISION: no user-presence flag on the SE key
//
// The key's access control is kSecAccessControlPrivateKeyUsage only; we do NOT
// add kSecAccessControlUserPresence / BiometryAny. The human-presence boundary
// is enforced by the Approver (LocalAuthentication) at secret-release time, and
// the daemon must be able to unwrap the vault data key at startup (launchd, no
// UI) without a prompt. Putting presence on the key would make every daemon
// start (and every Unwrap) pop Touch ID. Consequence: Tier() = TierHardware here
// means "key is hardware-bound and non-exportable", not "Unwrap prompts".
//
// # Blob format
//
// Wrap output is: 1 byte mode | 1 byte format version | payload. Unwrap refuses
// a blob whose mode differs from the store's active mode, instead of feeding
// garbage to a decryptor. See the format constants.
//
// # Memory
//
// Buffers this package owns (plaintext copies, the fallback KEK) are zeroed
// after use. CoreFoundation-owned immutable CFData returned by Security.framework
// (e.g. SecKeyCreateDecryptedData output) cannot be portably zeroed; we copy out
// and release it.
package darwin
