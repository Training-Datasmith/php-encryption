#!/usr/bin/env php
<?php
/**
 * Enforce exact PHPUnit success line and presence of every baseline test method.
 *
 * Usage: php scripts/check-phpunit-gate.php <phpunit-output.log> <junit.xml>
 */

if ($argc < 3) {
    fwrite(STDERR, "Usage: php scripts/check-phpunit-gate.php <log> <junit.xml>\n");
    exit(1);
}

$logPath = $argv[1];
$junitPath = $argv[2];
$root = dirname(__DIR__);

$expectedLinePath = $root . '/scripts/phpunit-expected-line.txt';
$baselineLinePath = $root . '/scripts/phpunit-baseline-line.txt';
$baselineTestsPath = $root . '/scripts/phpunit-baseline-tests.txt';

foreach (array($expectedLinePath, $baselineLinePath, $baselineTestsPath) as $p) {
    if (!is_readable($p)) {
        fwrite(STDERR, "Missing {$p}\n");
        exit(1);
    }
}

$expectedLine = trim(file_get_contents($expectedLinePath));
$baselineLine = trim(file_get_contents($baselineLinePath));
$log = file_get_contents($logPath);
if ($log === false) {
    fwrite(STDERR, "Cannot read log\n");
    exit(1);
}
$log = preg_replace('/\x1b\[[0-9;]*m/', '', $log);

if (preg_match('/^(?:PHP )?(Warning|Deprecated|Notice):/m', $log)) {
    fwrite(STDERR, "PHPUnit log contains PHP noise\n");
    exit(1);
}

if (strpos($log, $expectedLine) === false) {
    fwrite(STDERR, "Missing exact expected PHPUnit line: {$expectedLine}\n");
    exit(1);
}

// Baseline line must appear as substring only when running baseline-only; for full suite ensure counts relation.
if (preg_match('/OK \((\d+) tests?, (\d+) assertions?\)/', $expectedLine, $em)) {
    if (preg_match('/OK \((\d+) tests?, (\d+) assertions?\)/', $baselineLine, $bm)) {
        if ((int) $em[1] < (int) $bm[1]) {
            fwrite(STDERR, "Test count regressed below baseline\n");
            exit(1);
        }
        if ((int) $em[2] < (int) $bm[2]) {
            fwrite(STDERR, "Assertion count regressed below baseline\n");
            exit(1);
        }
    }
}

$xml = simplexml_load_file($junitPath);
if ($xml === false) {
    fwrite(STDERR, "Invalid junit xml\n");
    exit(1);
}

$cases = array();
foreach ($xml->xpath('//testcase') as $tc) {
    $cls = (string) $tc['class'];
    if ($cls === '' && isset($tc['classname'])) {
        $cls = str_replace('.', '\\', (string) $tc['classname']);
    }
    $name = (string) $tc['name'];
    $cases[] = array('class' => $cls, 'name' => $name);
}

$missing = array();
foreach (file($baselineTestsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    $line = trim($line);
    if ($line === '' || $line[0] === '#') {
        continue;
    }
    if (strpos($line, '::') === false) {
        $missing[] = $line . ' (invalid)';
        continue;
    }
    list($wantClass, $wantMethod) = explode('::', $line, 2);
    $found = false;
    foreach ($cases as $case) {
        $classOk = ($case['class'] === $wantClass)
            || (substr($case['class'], -strlen($wantClass)) === '\\' . $wantClass)
            || ($case['class'] === $wantClass);
        $name = $case['name'];
        $methodOk = ($name === $wantMethod)
            || (strpos($name, $wantMethod . ' ') === 0)
            || (strpos($name, $wantMethod . ' with data set') === 0);
        if ($classOk && $methodOk) {
            $found = true;
            break;
        }
    }
    if (!$found) {
        $missing[] = $line;
    }
}

if (count($missing) > 0) {
    fwrite(STDERR, "Baseline test methods missing from this run:\n");
    foreach ($missing as $m) {
        fwrite(STDERR, "  {$m}\n");
    }
    exit(1);
}

fwrite(STDOUT, "PHPUnit gate passed: {$expectedLine}\n");
exit(0);
