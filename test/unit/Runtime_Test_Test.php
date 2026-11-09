<?php

declare(strict_types=1);

use Defuse\Crypto\Runtime_Tests;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

class Runtime_Test_Test extends TestCase
{
    public function test_runtime_test()
    {
        Runtime_Tests::runtime_test();
    }
}
