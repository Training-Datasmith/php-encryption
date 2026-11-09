#!/usr/bin/env php
<?php
/**
 * PHP 7.2+: assert native null-salt resolution and prove mutation fails on executed temp Core.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

require __DIR__ . '/hkdf-null-salt-probe-helpers.php';
require dirname(__DIR__) . '/vendor/autoload.php';

use Defuse\Crypto\Core;

if (!function_exists('hash_hkdf')) {
    fwrite(STDERR, "hkdf-null-salt-native-probe: native hash_hkdf required.\n");
    exit(1);
}

$salt = Core::hkdf_prepare_salt_for_native(null);
if (!is_string($salt) || $salt !== '') {
    fwrite(STDERR, "Native null salt must resolve to empty string before hash_hkdf.\n");
    exit(1);
}

$digest_len = strlen(hash_hmac('sha256', '', '', true));
$fallbackSalt = Core::hkdf_prepare_salt_for_fallback(null, $digest_len);
if ($fallbackSalt === '' || $fallbackSalt !== str_repeat("\x00", $digest_len)) {
    fwrite(STDERR, "Fallback null salt preparer must yield HashLen zero bytes.\n");
    exit(1);
}

if (!hkdf_salt_probe_prove_mutation_fails('native', 'hkdf_mutate_prepare_native_source')) {
    fwrite(STDERR, "Native mutation probe: mutated Core should fail salt probe.\n");
    exit(1);
}

fwrite(STDOUT, "OK hkdf-null-salt native probe\n");
exit(0);
