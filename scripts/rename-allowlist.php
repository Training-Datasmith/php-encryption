<?php
/**
 * Site-scoped allowlist for third-party / framework identifiers defined in this repo.
 * Each entry: exact file path (relative to repo root), class short or namespaced name, method name.
 */
return array(
    'sites' => array(
        array(
            'file' => 'tests/Security/Ciphertext_Integrity_Test.php',
            'class' => 'Ciphertext_Integrity_Test',
            'method' => 'setUp',
        ),
        array(
            'file' => 'tests/Security/Ciphertext_Integrity_Test.php',
            'class' => 'Defuse\\Crypto\\Tests\\Security\\Ciphertext_Integrity_Test',
            'method' => 'setUp',
        ),
    ),
);
