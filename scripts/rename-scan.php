<?php
/**
 * Shared rename scanner: repo-owned camelCase methods need site-scoped allowlist entries (file + class + method).
 *
 * @param string $relativePath Path relative to repo root
 * @param string $content      File contents
 * @param array<int, array{file: string, class: string, method: string}> $allowSites
 * @param array<int, string> $oldNames Legacy identifiers that must not appear
 *
 * @return list<string> Failure messages (empty if clean)
 */
function rename_scan_content($relativePath, $content, array $allowSites, array $oldNames)
{
    $failures = array();

    foreach ($oldNames as $old) {
        if (strpos($content, $old) !== false) {
            $failures[] = "{$relativePath}: leftover old identifier {$old}";
        }
    }

    if (!preg_match('/\.php$/', $relativePath)) {
        return $failures;
    }

    $namespace = '';
    if (preg_match('/^\s*namespace\s+([^;]+);/m', $content, $nm)) {
        $namespace = trim($nm[1]);
    }

    $classByPos = array();
    if (preg_match_all('/^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $content, $classes, PREG_OFFSET_CAPTURE)) {
        foreach ($classes[1] as $pair) {
            $classByPos[$pair[1]] = $pair[0];
        }
    }

    $resolveClass = static function ($offset) use ($classByPos) {
        $name = 'global';
        foreach ($classByPos as $pos => $cn) {
            if ($pos <= $offset) {
                $name = $cn;
            }
        }
        return $name;
    };

    $isSiteAllowed = static function ($rel, $class, $method) use ($namespace, $allowSites) {
        $fq = $class === 'global'
            ? $class
            : ($namespace !== '' ? $namespace . '\\' . $class : $class);
        foreach ($allowSites as $site) {
            if ($site['file'] !== $rel) {
                continue;
            }
            $siteClass = $site['class'];
            if ($siteClass !== $class && $siteClass !== $fq) {
                continue;
            }
            if ($site['method'] === $method) {
                return true;
            }
        }
        return false;
    };

    $isStudlySnakeOrSimple = static function ($name) {
        if (in_array($name, array('HKDF', 'Crypto', 'Core', 'File', 'Key', 'Encoding'), true)) {
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

    if (preg_match_all('/^\s*(?:public|protected|private)?\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/m', $content, $m, PREG_OFFSET_CAPTURE)) {
        foreach ($m[1] as $pair) {
            $fn = $pair[0];
            $offset = $pair[1];
            $class = $resolveClass($offset);
            if ($isSnakeFunc($fn)) {
                continue;
            }
            if ($isSiteAllowed($relativePath, $class, $fn)) {
                continue;
            }
            $failures[] = "{$relativePath}: repo-owned method not snake_case: {$class}::{$fn}";
        }
    }

    if (preg_match_all('/^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $content, $classes)) {
        foreach ($classes[1] as $cn) {
            if (!$isStudlySnakeOrSimple($cn)) {
                $failures[] = "{$relativePath}: repo-owned class not Studly_Snake_Case: {$cn}";
            }
        }
    }

    return $failures;
}
