# php-encryption Architecture

## Purpose

Defuse Security's php-encryption provides authenticated symmetric encryption using AES-256-CTR with HMAC-SHA256 for integrity verification. It is designed to be misuse-resistant: the API makes it extremely difficult to accidentally produce insecure ciphertext.

## Directory Structure

```
src/
  Core.php                  — Constants, low-level crypto primitives (HKDF, PBKDF2, HMAC comparison)
  Crypto.php                — Public API: encrypt/decrypt strings with Key or password
  File.php                  — Public API: encrypt/decrypt files with Key or password
  Key.php                   — Opaque 256-bit random key container
  Key_Or_Password.php       — Unified key/password abstraction fed to encrypt_internal
  Key_Protected_By_Password.php — Password-wrapped key using PBKDF2
  Derived_Keys.php          — Holds the two sub-keys (encryption + authentication) derived per operation
  Encoding.php              — Hex ↔ binary codec with checksums for key serialisation
  Runtime_Tests.php         — Self-tests run before every encrypt/decrypt to detect broken environments
  Exception/
    Bad_Format_Exception.php
    Crypto_Exception.php
    Environment_Is_Broken_Exception.php
    IO_Exception.php
    Wrong_Key_Or_Modified_Ciphertext_Exception.php
```

## Ciphertext Format (V2)

```
VERSION (4 bytes) || SALT (32 bytes) || IV (16 bytes) || CIPHERTEXT (variable) || HMAC-SHA256 (32 bytes)
```

HMAC covers `VERSION || SALT || IV || CIPHERTEXT`, so any tampering is detected before decryption begins (Encrypt-then-MAC).

## Key Design Decisions

- **Encrypt-then-MAC**: HMAC is verified with a constant-time comparison (`hash_equals`) before any decryption is attempted, preventing padding oracle and chosen-ciphertext attacks.
- **Key separation**: HKDF derives independent encryption and authentication sub-keys from a single root key, preventing key-reuse vulnerabilities.
- **Password KDF**: `encrypt_with_password` uses PBKDF2-SHA256 internally (via `Key_Protected_By_Password`) to slow brute-force attempts.
- **No raw encryption surface**: `plain_encrypt` and `plain_decrypt` are `protected` helpers not meant for direct use; the only public API always applies authentication.
- **Runtime self-tests**: `Runtime_Tests::runtime_test()` fires before every operation to detect broken PHP builds.
- **`#[SensitiveParameter]`**: Keys and passwords are annotated so they are redacted from stack traces.

## Extension Points

- Implement `Key_Or_Password` to provide custom key derivation strategies.
- Override `Encoding` to use a different serialisation format for stored keys.

## Dependency Flow

```
Crypto / File
    └─ Key_Or_Password  (wraps Key or password string)
         └─ Derived_Keys  (two HKDF-derived sub-keys)
              └─ Core  (AES-256-CTR via openssl_encrypt, HMAC-SHA256, HKDF, PBKDF2)
                   └─ Encoding  (hex codec for key storage)
```
