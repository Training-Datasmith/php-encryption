#!/usr/bin/env php
<?php
/**
 * PHP 5.6 floor check: HKDF fallback must normalize null salt to HashLen zero bytes (RFC 5869).
 * PHP's hash_hmac() treats an empty key like a zero-filled key of block size, so output alone
 * cannot catch a null→'' regression; this script checks salt normalization, Core.php source, and
 * an in-memory source mutation, then runs HKDF on the fallback path (no hash_hkdf).
 */

$root = dirname(__DIR__);

spl_autoload_register(static function ($class) use ($root) {
    $prefix = 'Defuse\\Crypto\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $path = $root . '/src/' . $relative . '.php';
    if (is_readable($path)) {
        require $path;
    }
});

use Defuse\Crypto\Core;

if (function_exists('hash_hkdf')) {
    fwrite(STDERR, "hkdf-null-salt floor test must run without hash_hkdf (PHP 5.6 fallback).\n");
    exit(1);
}

$hash = 'sha256';
$digest_len = strlen(hash_hmac($hash, '', '', true));

$normalize_rfc = static function ($salt) use ($digest_len) {
    if (is_null($salt)) {
        return str_repeat("\x00", $digest_len);
    }
    return $salt;
};

$normalize_wrong = static function ($salt) {
    if (is_null($salt)) {
        return '';
    }
    return $salt;
};

if ($normalize_rfc(null) === $normalize_wrong(null)) {
    fwrite(STDERR, "Mutation check: RFC null salt must not normalize to empty string.\n");
    exit(1);
}

$coreSource = file_get_contents($root . '/src/Core.php');
if ($coreSource === false) {
    fwrite(STDERR, "Cannot read Core.php\n");
    exit(1);
}

$fallbackMarker = 'str_repeat("\x00", $digest_length)';
if (strpos($coreSource, $fallbackMarker) === false) {
    fwrite(STDERR, "HKDF fallback null-salt branch (str_repeat) missing from Core.php.\n");
    exit(1);
}

$mutatedSource = str_replace(
    "if (\\is_null(\$salt)) {\n            \$salt = \\str_repeat(\"\\x00\", \$digest_length);\n        }",
    "if (\\is_null(\$salt)) {\n            \$salt = '';\n        }",
    $coreSource
);
if ($mutatedSource === $coreSource) {
    fwrite(STDERR, "In-memory mutation: could not rewrite null-salt branch.\n");
    exit(1);
}
if (strpos($mutatedSource, $fallbackMarker) !== false) {
    fwrite(STDERR, "In-memory mutation: null-salt branch still present after rewrite.\n");
    exit(1);
}

$ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
$info = hex2bin('f1f301f1730f3f60242f5ad4d0386c0e');
$length = 42;

$with_null = Core::HKDF($hash, $ikm, $length, $info, null);
$with_hashlen_zeros = Core::HKDF($hash, $ikm, $length, $info, $normalize_rfc(null));

if ($with_null !== $with_hashlen_zeros) {
    fwrite(STDERR, "HKDF(null) must match explicit HashLen zero-byte salt on fallback path.\n");
    exit(1);
}

fwrite(STDOUT, "OK hkdf-null-salt floor test\n");
exit(0);
