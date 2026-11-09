#!/usr/bin/env php
<?php
/**
 * Fail if any tracked file sets display_errors (no swallowing warnings in CI).
 */

$root = dirname(__DIR__);
chdir($root);

$raw = shell_exec('git ls-files -z 2>/dev/null');
if (!is_string($raw)) {
    fwrite(STDERR, "check-no-display-errors: could not list tracked files.\n");
    exit(1);
}

$failures = array();
foreach (explode("\0", $raw) as $rel) {
    if ($rel === '' || !is_file($rel)) {
        continue;
    }
    if (!preg_match('/\.(php|sh|ini)$/i', $rel)) {
        continue;
    }
    $text = file_get_contents($rel);
    if ($text === false) {
        continue;
    }
    if (preg_match('/ini_set\s*\(\s*[\'"]display_errors[\'"]/i', $text)) {
        $failures[] = $rel;
    }
}

if (count($failures) > 0) {
    fwrite(STDERR, "check-no-display-errors: display_errors override in tracked files:\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  {$f}\n");
    }
    exit(1);
}

fwrite(STDOUT, "OK no-display-errors override\n");
exit(0);
