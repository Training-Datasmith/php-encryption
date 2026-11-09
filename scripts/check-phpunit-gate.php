#!/usr/bin/env php
<?php
/**
 * Gate PHPUnit output on a committed exact OK line (ANSI stripped). Baseline mode also checks junit method list.
 *
 * Usage: php scripts/check-phpunit-gate.php <baseline|added|full> <phpunit-output.log> [junit.xml]
 */

if ($argc < 3) {
    fwrite(STDERR, "Usage: php scripts/check-phpunit-gate.php <baseline|added|full> <log> [junit.xml]\n");
    exit(1);
}

$mode = $argv[1];
$logPath = $argv[2];
$junitPath = isset($argv[3]) ? $argv[3] : null;
$root = dirname(__DIR__);

$lineFiles = array(
    'baseline' => $root . '/scripts/phpunit-baseline-line.txt',
    'added' => $root . '/scripts/phpunit-added-line.txt',
    'full' => $root . '/scripts/phpunit-full-line.txt',
);

if (!isset($lineFiles[$mode])) {
    fwrite(STDERR, "Unknown mode: {$mode}\n");
    exit(1);
}

$expectedLine = trim(file_get_contents($lineFiles[$mode]));
if ($expectedLine === '') {
    fwrite(STDERR, "Empty expected line in {$lineFiles[$mode]}\n");
    exit(1);
}

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

$found = false;
foreach (explode("\n", $log) as $line) {
    if (rtrim($line, "\r") === $expectedLine) {
        $found = true;
        break;
    }
}
if (!$found) {
    fwrite(STDERR, "Missing exact PHPUnit line: {$expectedLine}\n");
    exit(1);
}

if ($mode === 'baseline') {
    if ($junitPath === null || !is_readable($junitPath)) {
        fwrite(STDERR, "Baseline gate requires junit xml\n");
        exit(1);
    }
    $baselineTestsPath = $root . '/scripts/phpunit-baseline-tests.txt';
    if (!is_readable($baselineTestsPath)) {
        fwrite(STDERR, "Missing baseline tests list\n");
        exit(1);
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
        $foundCase = false;
        foreach ($cases as $case) {
            $classOk = ($case['class'] === $wantClass)
                || (substr($case['class'], -strlen($wantClass)) === '\\' . $wantClass);
            $name = $case['name'];
            $methodOk = ($name === $wantMethod)
                || (strpos($name, $wantMethod . ' ') === 0)
                || (strpos($name, $wantMethod . ' with data set') === 0);
            if ($classOk && $methodOk) {
                $foundCase = true;
                break;
            }
        }
        if (!$foundCase) {
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
}

fwrite(STDOUT, "PHPUnit gate passed ({$mode}): {$expectedLine}\n");
exit(0);
