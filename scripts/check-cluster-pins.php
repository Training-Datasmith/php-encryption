#!/usr/bin/env php
<?php
/**
 * Verify cluster pins from composer-index; gap-lock phpunit on Packagist.
 * Includes in-memory wrong-SHA demos for installed.php and installed.json (no vendor writes).
 */

$root = dirname(__DIR__);
$indexCommit = '8d62da008404c9bdbbd7f3f86da9054d7ea9c48a';
$forbiddenOrgPhpunitShas = array(
    'a37d66fabf01af0eedabffe271b70dbe71723001',
    '698cbbc1e75a1ef1968f9cbfec89be056b288d0f',
);

$expected = array(
    // Empty: phpunit is a Packagist GAP — no org alias in composer.json.
);

$installedPhpPath = $root . '/vendor/composer/installed.php';
$installedJsonPath = $root . '/vendor/composer/installed.json';

if (!is_readable($installedPhpPath) || !is_readable($installedJsonPath)) {
    fwrite(STDERR, "check-cluster-pins: run composer update first (installed.php / installed.json missing).\n");
    exit(1);
}

/** @var array{versions?: array<string, array<string, mixed>>} $installedPhp */
$installedPhp = require $installedPhpPath;
$versions = isset($installedPhp['versions']) ? $installedPhp['versions'] : array();

$rawJson = file_get_contents($installedJsonPath);
/** @var array{packages?: list<array<string, mixed>>, packages-dev?: list<array<string, mixed>>} $jsonData */
$jsonData = json_decode($rawJson, true);
if (!is_array($jsonData)) {
    fwrite(STDERR, "check-cluster-pins: invalid installed.json.\n");
    exit(1);
}

$jsonPackages = array();
foreach (array_merge(
    isset($jsonData['packages']) ? $jsonData['packages'] : array(),
    isset($jsonData['packages-dev']) ? $jsonData['packages-dev'] : array()
) as $pkg) {
    if (isset($pkg['name'])) {
        $jsonPackages[$pkg['name']] = $pkg;
    }
}

$normalizeSha = static function ($sha) {
    return is_string($sha) ? strtolower($sha) : '';
};

$failures = 0;

foreach ($expected as $name => $want) {
    if (!isset($versions[$name])) {
        fwrite(STDERR, "check-cluster-pins: {$name} is not installed.\n");
        $failures++;
        continue;
    }
    $meta = $versions[$name];
    $aliases = isset($meta['aliases']) && is_array($meta['aliases']) ? $meta['aliases'] : array();
    if (!in_array($want['alias'], $aliases, true)) {
        fwrite(STDERR, "check-cluster-pins: {$name} alias mismatch.\n");
        $failures++;
    }
    $ref = isset($meta['reference']) ? $meta['reference'] : '';
    if (!is_string($ref) || !hash_equals($want['reference'], $ref)) {
        fwrite(STDERR, "check-cluster-pins: {$name} installed.php reference mismatch.\n");
        $failures++;
    }
    if (!isset($jsonPackages[$name]['source']['reference'])) {
        fwrite(STDERR, "check-cluster-pins: {$name} missing from installed.json.\n");
        $failures++;
        continue;
    }
    $jsonRef = $jsonPackages[$name]['source']['reference'];
    if ($normalizeSha($jsonRef) !== $normalizeSha($want['reference'])) {
        fwrite(STDERR, "check-cluster-pins: {$name} installed.json reference mismatch.\n");
        $failures++;
    }
}

foreach ($jsonPackages as $name => $pkg) {
    if ($name === 'phpunit/phpunit') {
        continue;
    }
    $url = isset($pkg['source']['url']) ? (string) $pkg['source']['url'] : '';
    if (strpos($url, 'Training-Datasmith') !== false && !isset($expected[$name])) {
        fwrite(STDERR, "check-cluster-pins: unexpected org package {$name} without root alias.\n");
        $failures++;
    }
}

if (!isset($versions['phpunit/phpunit']) || !isset($jsonPackages['phpunit/phpunit'])) {
    fwrite(STDERR, "check-cluster-pins: phpunit/phpunit must be installed.\n");
    $failures++;
} else {
    $puMeta = $versions['phpunit/phpunit'];
    $puJson = $jsonPackages['phpunit/phpunit'];
    $refPhp = $normalizeSha(isset($puMeta['reference']) ? $puMeta['reference'] : '');
    $refJson = $normalizeSha(isset($puJson['source']['reference']) ? $puJson['source']['reference'] : '');
    $url = isset($puJson['source']['url']) ? (string) $puJson['source']['url'] : '';
    $version = isset($puJson['version']) ? (string) $puJson['version'] : '';

    if ($refPhp === '' || strlen($refPhp) !== 40 || $refJson === '' || $refPhp !== $refJson) {
        fwrite(STDERR, "check-cluster-pins: phpunit/phpunit reference missing or inconsistent across install snapshots.\n");
        $failures++;
    }
    if (in_array($refPhp, $forbiddenOrgPhpunitShas, true)) {
        fwrite(STDERR, "check-cluster-pins: phpunit/phpunit must not be org index SHA at commit {$indexCommit}.\n");
        $failures++;
    }
    if (strpos($url, 'Training-Datasmith') !== false) {
        fwrite(STDERR, "check-cluster-pins: phpunit/phpunit must come from Packagist, not Training-Datasmith.\n");
        $failures++;
    }
    if (strpos($url, 'sebastianbergmann/phpunit') === false && strpos($url, 'github.com/sebastianbergmann/phpunit') === false) {
        fwrite(STDERR, "check-cluster-pins: phpunit/phpunit source url unexpected: {$url}\n");
        $failures++;
    }
    $normalized = ltrim($version, 'vV');
    if ($normalized === '' || version_compare($normalized, '8.5.52', '<') || version_compare($normalized, '9.0.0', '>=')) {
        fwrite(STDERR, "check-cluster-pins: phpunit/phpunit version {$version} does not satisfy ^8.5.52.\n");
        $failures++;
    }
    fwrite(STDOUT, "check-cluster-pins: gap phpunit/phpunit {$version} from Packagist.\n");
}

if ($failures > 0) {
    exit(1);
}

$demoPackage = 'defuse/pin-check-demo';
$demoAlias = '8.5.52';
$goodSha = '0123456789abcdef0123456789abcdef01234567';
$badSha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

$assertPhpSide = static function (array $versionsMap, $name, array $want) {
    if (!isset($versionsMap[$name])) {
        return false;
    }
    $meta = $versionsMap[$name];
    $aliases = isset($meta['aliases']) && is_array($meta['aliases']) ? $meta['aliases'] : array();
    if (!in_array($want['alias'], $aliases, true)) {
        return false;
    }
    $ref = isset($meta['reference']) ? $meta['reference'] : '';
    if (!is_string($ref) || !hash_equals($want['reference'], $ref)) {
        return false;
    }
    return true;
};

$assertJsonSide = static function (array $jsonPkgs, $name, array $want) use ($normalizeSha) {
    if (!isset($jsonPkgs[$name]['source']['reference'])) {
        return false;
    }
    return $normalizeSha($jsonPkgs[$name]['source']['reference']) === $normalizeSha($want['reference']);
};

$assertDemoPackage = static function (array $versionsMap, array $jsonPkgs, $name, array $want) use ($assertPhpSide, $assertJsonSide) {
    return $assertPhpSide($versionsMap, $name, $want) && $assertJsonSide($jsonPkgs, $name, $want);
};

$demoExpected = array(
    $demoPackage => array('alias' => $demoAlias, 'reference' => $goodSha),
);

$versionsDemo = $versions;
$versionsDemo[$demoPackage] = array(
    'reference' => $goodSha,
    'aliases' => array($demoAlias),
);
$jsonDemo = $jsonPackages;
$jsonDemo[$demoPackage] = array(
    'name' => $demoPackage,
    'source' => array('reference' => $goodSha, 'url' => 'https://github.com/example/demo.git'),
);

$snapshotVersions = $versionsDemo;
$snapshotJson = $jsonDemo;

$versionsBadPhp = $snapshotVersions;
$versionsBadPhp[$demoPackage]['reference'] = $badSha;

if ($assertPhpSide($versionsBadPhp, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo did not fail on installed.php side.\n");
    exit(1);
}
if (!$assertJsonSide($snapshotJson, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo: unmutated installed.json side should still pass.\n");
    exit(1);
}
if (!$assertDemoPackage($snapshotVersions, $snapshotJson, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo: original snapshot should pass both sides.\n");
    exit(1);
}
fwrite(STDOUT, "check-cluster-pins: wrong-SHA demo failed on installed.php only.\n");

$jsonBad = $snapshotJson;
$jsonBad[$demoPackage]['source']['reference'] = $badSha;

if ($assertJsonSide($jsonBad, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo did not fail on installed.json side.\n");
    exit(1);
}
if (!$assertPhpSide($snapshotVersions, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo: unmutated installed.php side should still pass.\n");
    exit(1);
}
if (!$assertDemoPackage($snapshotVersions, $snapshotJson, $demoPackage, $demoExpected[$demoPackage])) {
    fwrite(STDERR, "check-cluster-pins: wrong-SHA demo: original snapshot should pass after json mutation demo.\n");
    exit(1);
}
fwrite(STDOUT, "check-cluster-pins: wrong-SHA demo failed on installed.json only.\n");

$count = count($expected);
fwrite(STDOUT, "check-cluster-pins: all cluster packages match expected SHAs and aliases ({$count} packages).\n");
exit(0);
