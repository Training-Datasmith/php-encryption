#!/usr/bin/env php
<?php
/**
 * Make src/ parse on PHP 5.6 (strip strict_types, public const, 7+ type hints).
 */
$root = dirname(__DIR__) . '/src';
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
foreach ($it as $file) {
    if (!$file->isFile() || $file->getExtension() !== 'php') {
        continue;
    }
    $path = $file->getPathname();
    $text = file_get_contents($path);
    $orig = $text;
    $text = preg_replace('/^\s*declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*\n/m', '', $text);
    $text = preg_replace('/\bpublic\s+const\b/', 'const', $text);
    if (basename($path) === 'Derived_Keys.php') {
        $text = preg_replace('/public function get_authentication_key\(\): string/', 'public function get_authentication_key()', $text);
        $text = preg_replace('/public function get_encryption_key\(\): string/', 'public function get_encryption_key()', $text);
        $text = preg_replace(
            '/public function __construct\(\s*#\[\\\\SensitiveParameter\]\s*string \$akey,\s*#\[\\\\SensitiveParameter\]\s*string \$ekey\s*\)/s',
            "public function __construct(\n        #[\\SensitiveParameter]\n        \$akey,\n        #[\\SensitiveParameter]\n        \$ekey\n    )",
            $text
        );
    }
    if (basename($path) === 'Key_Or_Password.php') {
        $text = preg_replace('/public static function create_from_key\(Key \$key\): self/', 'public static function create_from_key(Key $key)', $text);
        $text = preg_replace(
            '/public static function create_from_password\(\s*#\[\\\\SensitiveParameter\]\s*string \$password\s*\): self/',
            "public static function create_from_password(\n        #[\\SensitiveParameter]\n        \$password\n    )",
            $text
        );
        $text = preg_replace('/public function derive_keys\(string \$salt\): Derived_Keys/', 'public function derive_keys($salt)', $text);
    }
    if ($text !== $orig) {
        file_put_contents($path, $text);
    }
}
