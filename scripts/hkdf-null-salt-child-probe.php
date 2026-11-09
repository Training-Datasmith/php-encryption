#!/usr/bin/env php
<?php
/**
 * Child probe: observe salt preparation on a copied src tree (argv: mode srcRoot).
 */

error_reporting(E_ALL);

if ($argc < 3) {
    fwrite(STDERR, "Usage: hkdf-null-salt-child-probe.php <native|fallback> <srcRoot>\n");
    exit(2);
}

$mode = $argv[1];
$srcRoot = $argv[2];

if (!is_dir($srcRoot)) {
    exit(1);
}

spl_autoload_register(static function ($class) use ($srcRoot) {
    $prefix = 'Defuse\\Crypto\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
    $path = $srcRoot . '/' . $relative . '.php';
    if (is_readable($path)) {
        require $path;
    }
});

require_once $srcRoot . '/Core.php';

if ($mode === 'native') {
    $salt = \Defuse\Crypto\Core::hkdf_prepare_salt_for_native(null);
    if (!is_string($salt) || $salt !== '') {
        exit(1);
    }
    exit(0);
}

if ($mode === 'fallback') {
    $digest_len = strlen(hash_hmac('sha256', '', '', true));
    $salt = \Defuse\Crypto\Core::hkdf_prepare_salt_for_fallback(null, $digest_len);
    if (!is_string($salt) || $salt === '') {
        exit(1);
    }
    if ($salt !== str_repeat("\x00", $digest_len)) {
        exit(1);
    }
    exit(0);
}

exit(2);
