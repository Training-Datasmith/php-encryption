#!/usr/bin/env php
<?php
/**
 * PHP 5.6: fallback null-salt resolution and executed temp-Core mutation probe.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

require __DIR__ . '/hkdf-null-salt-probe-helpers.php';

$root = dirname(__DIR__);
hkdf_salt_probe_autoload_register($root . '/src');
require $root . '/src/Core.php';

use Defuse\Crypto\Core;

if (function_exists('hash_hkdf')) {
    fwrite(STDERR, "hkdf-null-salt floor test must run without hash_hkdf (PHP 5.6 fallback).\n");
    exit(1);
}

$digest_len = strlen(hash_hmac('sha256', '', '', true));
$salt = Core::hkdf_prepare_salt_for_fallback(null, $digest_len);
if (!is_string($salt) || $salt === '' || $salt !== str_repeat("\x00", $digest_len)) {
    fwrite(STDERR, "Fallback null salt must be HashLen zero bytes before hash_hmac.\n");
    exit(1);
}

$ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
$info = hex2bin('f1f301f1730f3f60242f5ad4d0386c0e');
$length = 42;
$with_null = Core::HKDF('sha256', $ikm, $length, $info, null);
$with_explicit = Core::HKDF('sha256', $ikm, $length, $info, $salt);
if ($with_null !== $with_explicit) {
    fwrite(STDERR, "HKDF(null) must use prepared fallback salt.\n");
    exit(1);
}

if (!hkdf_salt_probe_prove_mutation_fails('fallback', 'hkdf_mutate_prepare_fallback_source')) {
    fwrite(STDERR, "Fallback mutation probe: mutated Core should fail salt probe.\n");
    exit(1);
}

fwrite(STDOUT, "OK hkdf-null-salt floor test\n");
exit(0);
