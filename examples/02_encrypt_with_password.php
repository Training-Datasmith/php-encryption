<?php

declare(strict_types=1);

/**
 * Example: Encrypting and decrypting a string with a human-chosen password.
 *
 * Use this when you must derive an encryption key from a user-supplied password
 * rather than storing a random key.  Internally this uses PBKDF2-SHA256 to
 * stretch the password, making brute-force attacks significantly more expensive.
 *
 * Security notes:
 *  - Password-based encryption is inherently weaker than key-based encryption
 *    for high-value secrets.  Prefer Key-based encryption when practical.
 *  - The password is never stored — only the ciphertext.  Losing the password
 *    means losing the data.
 *  - Use a strong, unique password (ideally machine-generated and stored in a
 *    password manager) rather than a user-typed passphrase for sensitive data.
 *  - The #[SensitiveParameter] attribute on the password argument ensures the
 *    value is redacted from PHP stack traces.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Defuse\Crypto\Crypto;

$password  = 's3cr3t-p@ssw0rd-example';   // Use a strong password in production.
$plaintext = 'Sensitive configuration value';

$ciphertext = Crypto::encrypt_with_password($plaintext, $password);
echo 'Ciphertext: ' . $ciphertext . PHP_EOL;

$decrypted = Crypto::decrypt_with_password($ciphertext, $password);
echo 'Decrypted: ' . $decrypted . PHP_EOL;

assert($decrypted === $plaintext, 'Round-trip failed!');
echo 'Round-trip OK.' . PHP_EOL;

// Demonstrate that a wrong password is detected and rejected.
try {
    Crypto::decrypt_with_password($ciphertext, 'wrong-password');
    echo 'ERROR: should have thrown!' . PHP_EOL;
} catch (\Defuse\Crypto\Exception\Wrong_Key_Or_Modified_Ciphertext_Exception $e) {
    echo 'Correctly rejected wrong password: ' . $e->getMessage() . PHP_EOL;
}
