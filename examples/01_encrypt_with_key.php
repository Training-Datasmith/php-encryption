<?php

declare(strict_types=1);

/**
 * Example: Encrypting and decrypting a string with a randomly-generated Key.
 *
 * This is the recommended approach for application-level symmetric encryption.
 * The Key contains 256 bits of cryptographically random material and should be
 * stored securely (e.g., in an environment variable or secret manager).
 *
 * Security notes:
 *  - Never log or display the raw key bytes.
 *  - Keys serialised with save_to_ascii_safe_string() include a checksum;
 *    do NOT base64-encode or otherwise transform them before storing.
 *  - Reusing a Key for many messages is safe — a fresh random IV and salt are
 *    generated on every encrypt() call.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

// --- Key management ----------------------------------------------------------

// Generate once; persist the ASCII string to your secret store.
$key = Key::create_new_random_key();
$stored_key = $key->save_to_ascii_safe_string();

echo 'Stored key (save this securely): ' . $stored_key . PHP_EOL;

// Later: load the key back from storage.
$loaded_key = Key::load_from_ascii_safe_string($stored_key);

// --- Encryption / decryption -------------------------------------------------

$plaintext = 'Hello, world! This is a secret message.';

$ciphertext = Crypto::encrypt($plaintext, $loaded_key);
echo 'Ciphertext (hex): ' . $ciphertext . PHP_EOL;

$decrypted = Crypto::decrypt($ciphertext, $loaded_key);
echo 'Decrypted: ' . $decrypted . PHP_EOL;

assert($decrypted === $plaintext, 'Round-trip failed!');
echo 'Round-trip OK.' . PHP_EOL;
