#!/usr/bin/env php
<?php
/**
 * Fail on leftover pre-rename repo identifiers or repo-owned camelCase outside site allowlist.
 */

$root = dirname(__DIR__);
require __DIR__ . '/rename-scan.php';

$allowlist = require __DIR__ . '/rename-allowlist.php';
$allowSites = isset($allowlist['sites']) ? $allowlist['sites'] : array();

$oldNames = array(
    'incrementCounter', 'secureRandom', 'hashEquals', 'ensureConstantExists', 'ensureFunctionExists',
    'ensureTrue', 'ourStrlen', 'ourSubstr', 'encryptWithPassword', 'decryptWithPassword', 'legacyDecrypt',
    'encryptInternal', 'decryptInternal', 'plainEncrypt', 'plainDecrypt', 'verifyHMAC', 'binToHex', 'hexToBin',
    'trimTrailingWhitespace', 'encryptFile', 'decryptFile', 'createNewRandomKey', 'loadFromAsciiSafeString',
    'saveToAsciiSafeString', 'DerivedKeys', 'KeyOrPassword', 'KeyProtectedByPassword', 'RuntimeTests',
    'BadFormatException', 'CryptoException', 'EnvironmentIsBrokenException', 'IOException',
    'WrongKeyOrModifiedCiphertextException', 'BackwardsCompatibilityTest', 'CoreTest', 'CryptoTest',
);

$scanDirs = array('src', 'test', 'tests', 'docs', 'examples', 'bin');
$paths = array();
foreach ($scanDirs as $dir) {
    $full = $root . '/' . $dir;
    if (!is_dir($full)) {
        continue;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($full));
    foreach ($it as $file) {
        if ($file->isFile() && preg_match('/\.(php|md)$/', $file->getFilename())) {
            $paths[] = $file->getPathname();
        }
    }
}
foreach (array('README.md', 'ARCHITECTURE.md') as $extra) {
    if (is_file($root . '/' . $extra)) {
        $paths[] = $root . '/' . $extra;
    }
}

$failures = array();
foreach ($paths as $path) {
    $rel = str_replace($root . '/', '', $path);
    $text = file_get_contents($path);
  $failures = array_merge($failures, rename_scan_content($rel, $text, $allowSites, $oldNames));
}

// In-memory demos using the real scanner (not a parallel code path).
$demoWrongSite = <<<'PHP'
<?php
namespace Defuse\Crypto\Tests\Security;

use PHPUnit\Framework\TestCase;

class Wrong_Site_SetUp_Test extends TestCase
{
    protected function setUp(): void
    {
    }
}
PHP;
$wrongFailures = rename_scan_content('demo/Wrong_Site_SetUp_Test.php', $demoWrongSite, $allowSites, array());
if (count($wrongFailures) === 0) {
    $failures[] = 'rename-check: setUp at unlisted site must be rejected';
} else {
    fwrite(STDOUT, "rename-check: in-memory demo rejected setUp at unlisted site.\n");
}

$demoListedSite = <<<'PHP'
<?php
namespace Defuse\Crypto\Tests\Security;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;

class Ciphertext_Integrity_Test extends TestCase
{
    protected function setUp(): void
    {
        $this->key = Key::create_new_random_key();
    }

    public function test_demo(): void
    {
    }
}
PHP;
$listedFailures = rename_scan_content('tests/Security/Ciphertext_Integrity_Test.php', $demoListedSite, $allowSites, array());
if (count($listedFailures) !== 0) {
    foreach ($listedFailures as $lf) {
        $failures[] = 'rename-check: setUp at allowlisted site wrongly flagged: ' . $lf;
    }
} else {
    fwrite(STDOUT, "rename-check: in-memory demo accepted setUp at allowlisted site.\n");
}

$demoCamelRepo = <<<'PHP'
<?php
class Demo_Repo_Owned {
    public function doBadThing() {}
}
PHP;
$camelFailures = rename_scan_content('demo/Demo_Repo_Owned.php', $demoCamelRepo, $allowSites, array());
if (count($camelFailures) === 0) {
    $failures[] = 'rename-check: generic camelCase repo-owned name must be rejected';
} else {
    fwrite(STDOUT, "rename-check: in-memory demo rejected generic camelCase repo method.\n");
}

if (count($failures) > 0) {
    foreach ($failures as $f) {
        fwrite(STDERR, $f . "\n");
    }
    exit(1);
}

fwrite(STDOUT, "OK rename-check\n");
exit(0);
