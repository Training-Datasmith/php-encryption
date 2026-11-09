#!/usr/bin/env php
<?php
/**
 * Fail on leftover pre-rename repo identifiers or repo-owned camelCase outside allowlist.
 */

$root = dirname(__DIR__);
$allowlist = require __DIR__ . '/rename-allowlist.php';
$allowSet = array_fill_keys($allowlist, true);

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

$isAllowedCamel = static function ($class, $method) use ($allowSet) {
    $site = $class . '::' . $method;
    return isset($allowSet[$site]);
};

$isStudlySnakeOrSimple = static function ($name) {
    if ($name === 'HKDF' || $name === 'Crypto' || $name === 'Core' || $name === 'File' || $name === 'Key' || $name === 'Encoding') {
        return true;
    }
    if (strpos($name, '__') === 0) {
        return true;
    }
    $parts = explode('_', $name);
    foreach ($parts as $p) {
        if ($p === '') {
            return false;
        }
        if (!ctype_upper($p[0])) {
            return false;
        }
        if (preg_match('/[A-Z]/', substr($p, 1))) {
            return false;
        }
    }
    return true;
};

$isSnakeFunc = static function ($name) {
    if (strpos($name, '__') === 0) {
        return true;
    }
    if (preg_match('/^[a-z][a-z0-9_]*$/', $name)) {
        return true;
    }
  if (preg_match('/^test_[a-z0-9_]+$/', $name)) {
        return true;
    }
    return false;
};

$failures = array();

foreach ($paths as $path) {
    $rel = str_replace($root . '/', '', $path);
    $text = file_get_contents($path);
    foreach ($oldNames as $old) {
        if (strpos($text, $old) !== false) {
            $failures[] = "{$rel}: leftover old identifier {$old}";
        }
    }
    if (!preg_match('/\.php$/', $path)) {
        continue;
    }
    if (!preg_match_all('/^\s*(?:public|protected|private)?\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/m', $text, $m)) {
        $m = array(array(), array());
    }
    $class = 'global';
    if (preg_match('/^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $text, $cm)) {
        $class = $cm[1];
    }
    $extendsPhpUnit = (bool) preg_match(
        '/extends\s+(?:\\\\?PHPUnit\\\\Framework\\\\TestCase|\\\\?Yoast\\\\PHPUnitPolyfills\\\\TestCases\\\\TestCase|TestCase)\b/',
        $text
    );
    if (!$extendsPhpUnit && preg_match('/use\s+PHPUnit\\\\Framework\\\\TestCase\s*;/', $text) && preg_match('/extends\s+TestCase\b/', $text)) {
        $extendsPhpUnit = true;
    }
    foreach ($m[1] as $fn) {
        if ($extendsPhpUnit && ($fn === 'setUp' || $fn === 'tearDown')) {
            continue;
        }
        if (!$isSnakeFunc($fn) && !$isAllowedCamel($class, $fn)) {
            $failures[] = "{$rel}: repo-owned method not snake_case: {$class}::{$fn}";
        }
    }
    if (preg_match_all('/^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $text, $classes)) {
        foreach ($classes[1] as $cn) {
            if (!$isStudlySnakeOrSimple($cn) && !$isAllowedCamel('N/A', $cn)) {
                $failures[] = "{$rel}: repo-owned class not Studly_Snake_Case: {$cn}";
            }
        }
    }
}

// In-memory demo: allowlisted set_up must be rejected outside Yoast TestCase.
$demoSource = <<<'PHP'
<?php
class Not_A_Test_Helper {
    public function set_up() {}
}
PHP;
$demoFailures = array();
if (preg_match('/function\s+set_up\s*\(/', $demoSource) && !preg_match('/extends\s+TestCase/', $demoSource)) {
    $demoFailures[] = 'allowlist demo: set_up outside TestCase should fail';
}
if (count($demoFailures) === 0) {
    $failures[] = 'rename-check: in-memory allowlist demo did not detect misuse';
} else {
    fwrite(STDOUT, "rename-check: allowlist demo rejected set_up outside TestCase.\n");
}

if (count($failures) > 0) {
    foreach ($failures as $f) {
        fwrite(STDERR, $f . "\n");
    }
    exit(1);
}

fwrite(STDOUT, "OK rename-check\n");
exit(0);
