#!/usr/bin/env php
<?php
/**
 * Lint every file under src/ with php -l on PHP 5.6 floor image (invoked inside container).
 */
$root = dirname(__DIR__);
$src = $root . '/src';
$count = 0;
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
foreach ($it as $file) {
    if (!$file->isFile() || $file->getExtension() !== 'php') {
        continue;
    }
    $path = $file->getPathname();
    $count++;
    $cmd = 'php -l ' . escapeshellarg($path) . ' 2>&1';
    $out = array();
    $code = 0;
    exec($cmd, $out, $code);
    $line = implode("\n", $out);
    if ($code !== 0 || strpos($line, 'No syntax errors detected') === false) {
        fwrite(STDERR, $line . "\n");
        exit(1);
    }
    fwrite(STDOUT, $line . "\n");
}
fwrite(STDOUT, "OK lint ({$count} files)\n");
exit(0);
