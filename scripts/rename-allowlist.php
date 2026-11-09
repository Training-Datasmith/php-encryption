<?php
/**
 * Site-scoped allowlist for third-party / PHP-native identifiers during rename-check.
 * Keys: Class::method or Class::method::param
 */
return array(
    'Yoast\\PHPUnitPolyfills\\TestCases\\TestCase::set_up',
    'Yoast\\PHPUnitPolyfills\\TestCases\\TestCase::tear_down',
    'PHPUnit\\Framework\\TestCase::setUp',
    'PHPUnit\\Framework\\TestCase::tearDown',
    'PHPUnit\\Framework\\TestCase::assertSame',
    'PHPUnit\\Framework\\TestCase::assertTrue',
    'PHPUnit\\Framework\\TestCase::assertFalse',
    'PHPUnit\\Framework\\TestCase::assertEquals',
    'PHPUnit\\Framework\\TestCase::expectException',
    'PHPUnit\\Framework\\TestCase::expectExceptionMessage',
    'PHPUnit\\Framework\\TestCase::fail',
    'Defuse\\Crypto\\Core::HKDF',
    'Defuse\\Crypto\\Core::pbkdf2',
);
