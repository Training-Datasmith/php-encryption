<?php
/**
 * HKDF null-salt temp-tree copy, child-process probes, and mutations (never mutates repo src/).
 */

function hkdf_salt_probe_autoload_register($srcRoot)
{
    spl_autoload_register(static function ($class) use ($srcRoot) {
        $prefix = 'Defuse\\Crypto\\';
        if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
            return;
        }
        $relative = str_replace('\\', '/', substr($class, strlen($prefix)));
        $path = $srcRoot . '/' . $relative . '.php';
        if (is_readable($path)) {
            require $path;
        }
    });
}

/**
 * @return string|false
 */
function hkdf_salt_probe_copy_src_tree($destRoot)
{
    $srcRoot = dirname(__DIR__) . '/src';
    if (!is_dir($srcRoot)) {
        return false;
    }
    if (!is_dir($destRoot) && !mkdir($destRoot, 0700, true) && !is_dir($destRoot)) {
        return false;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($srcRoot, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $item) {
        $target = $destRoot . '/' . $iterator->getSubPathName();
        if ($item->isDir()) {
            if (!is_dir($target) && !mkdir($target, 0700, true) && !is_dir($target)) {
                return false;
            }
        } elseif (!copy($item->getPathname(), $target)) {
            return false;
        }
    }
    return $destRoot;
}

function hkdf_salt_probe_rmtree($dir)
{
    if (!is_dir($dir)) {
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            rmdir($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }
    rmdir($dir);
}

/**
 * @param string $mode native|fallback
 *
 * @return bool
 */
function hkdf_salt_probe_check_core_in_tree($srcRoot, $mode)
{
    hkdf_salt_probe_autoload_register($srcRoot);
    if (!class_exists('Defuse\\Crypto\\Core', false)) {
        require_once $srcRoot . '/Core.php';
    }
    if ($mode === 'native') {
        $salt = \Defuse\Crypto\Core::hkdf_prepare_salt_for_native(null);
        if (!is_string($salt) || $salt !== '') {
            return false;
        }
        return true;
    }
    if ($mode === 'fallback') {
        $digest_len = strlen(hash_hmac('sha256', '', '', true));
        $salt = \Defuse\Crypto\Core::hkdf_prepare_salt_for_fallback(null, $digest_len);
        if (!is_string($salt) || $salt === '') {
            return false;
        }
        return $salt === str_repeat("\x00", $digest_len);
    }
    return false;
}

/**
 * @param string $srcRoot
 * @param string $mode
 *
 * @return bool true when child exits 0
 */
function hkdf_salt_probe_run_child($srcRoot, $mode)
{
    $child = dirname(__FILE__) . '/hkdf-null-salt-child-probe.php';
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($child) . ' '
        . escapeshellarg($mode) . ' ' . escapeshellarg($srcRoot) . ' 2>&1';
    $lines = array();
    $code = 0;
    exec($cmd, $lines, $code);

    return $code === 0;
}

/**
 * @param string   $mode native|fallback
 * @param callable $mutate function (string $corePhp): string
 *
 * @return bool true when mutation correctly breaks the probe
 */
function hkdf_salt_probe_prove_mutation_fails($mode, $mutate)
{
    $tmpdir = sys_get_temp_dir() . '/defuse-hkdf-' . bin2hex(openssl_random_pseudo_bytes(6));
    $copyRoot = hkdf_salt_probe_copy_src_tree($tmpdir);
    if ($copyRoot === false) {
        throw new RuntimeException('Could not copy src to temp');
    }

    try {
        if (!hkdf_salt_probe_run_child($copyRoot, $mode)) {
            throw new RuntimeException('Unmutated temp Core failed salt probe');
        }

        $corePath = $copyRoot . '/Core.php';
        $source = file_get_contents($corePath);
        if ($source === false) {
            throw new RuntimeException('Could not read copied Core.php');
        }
        if (is_string($mutate)) {
            $mutated = call_user_func($mutate, $source);
        } else {
            $mutated = $mutate($source);
        }
        if ($mutated === $source) {
            throw new RuntimeException('Mutation did not change Core.php');
        }
        if (file_put_contents($corePath, $mutated) === false) {
            throw new RuntimeException('Could not write mutated Core.php');
        }

        if (hkdf_salt_probe_run_child($copyRoot, $mode)) {
            return false;
        }
        return true;
    } finally {
        hkdf_salt_probe_rmtree($tmpdir);
    }
}

function hkdf_mutate_prepare_native_source($source)
{
    $search = "    public static function hkdf_prepare_salt_for_native(\$salt)\n    {\n        if (\\is_null(\$salt)) {\n            \$salt = '';\n        }\n        return \$salt;\n    }";
    $replace = "    public static function hkdf_prepare_salt_for_native(\$salt)\n    {\n        return \$salt;\n    }";
    if (strpos($source, $search) === false) {
        return $source;
    }
    return str_replace($search, $replace, $source);
}

function hkdf_mutate_prepare_fallback_source($source)
{
    $search = "    public static function hkdf_prepare_salt_for_fallback(\$salt, \$digest_length)\n    {\n        if (\\is_null(\$salt)) {\n            \$salt = \\str_repeat(\"\\x00\", \$digest_length);\n        }\n        return \$salt;\n    }";
    $replace = "    public static function hkdf_prepare_salt_for_fallback(\$salt, \$digest_length)\n    {\n        return \$salt;\n    }";
    if (strpos($source, $search) === false) {
        return $source;
    }
    return str_replace($search, $replace, $source);
}
