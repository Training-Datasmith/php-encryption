<?php

declare(strict_types=1);

/**
 * Example: Encrypting and decrypting a file with a Key.
 *
 * File::encrypt_file() streams the file in 1 MiB chunks, so large files are
 * handled without loading the entire contents into memory.
 *
 * Security notes:
 *  - The plaintext input file is NOT deleted automatically.  After encryption
 *    you should securely wipe or delete the original file if it must not remain
 *    on disk in plaintext.
 *  - The output file is written atomically to a temporary path on the same
 *    filesystem, then renamed, preventing partial writes from leaving
 *    unverified ciphertext.
 *  - HMAC authentication covers the entire file; decryption fails if any byte
 *    has been altered.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Defuse\Crypto\File;
use Defuse\Crypto\Key;

$key = Key::create_new_random_key();

// Create a temporary plaintext file.
$plaintext_file  = sys_get_temp_dir() . '/defuse_example_plain.txt';
$encrypted_file  = sys_get_temp_dir() . '/defuse_example_enc.bin';
$decrypted_file  = sys_get_temp_dir() . '/defuse_example_dec.txt';

file_put_contents($plaintext_file, 'This is the secret file content.');

// Encrypt the file.
File::encrypt_file($plaintext_file, $encrypted_file, $key);
echo 'Encrypted file written to: ' . $encrypted_file . PHP_EOL;

// Decrypt the file.
File::decrypt_file($encrypted_file, $decrypted_file, $key);
echo 'Decrypted content: ' . file_get_contents($decrypted_file) . PHP_EOL;

assert(
    file_get_contents($plaintext_file) === file_get_contents($decrypted_file),
    'File round-trip failed!'
);
echo 'File round-trip OK.' . PHP_EOL;

// Clean up.
unlink($plaintext_file);
unlink($encrypted_file);
unlink($decrypted_file);
