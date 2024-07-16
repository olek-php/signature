<?php

namespace Olek\Tests;

use Olek\Signature\Generator;
use PHPUnit\Framework\TestCase;

class GeneratorTest extends TestCase
{
    private const RESULT = "t=1721126075,s=80b4667b0a0981105972018700fe86e7e30c91752e05af0d8f1f5a7d3c84732faecbb7971bedf966e8449114e7207a72b9dc8973ee88bf71a0c3835acf2a2177";
    private const RESULT_WITH_PAYLOAD = "t=1721126075,s=a21c4a9adc22a37de5c6c863b99a383adf27f622106bd655fae60552282815153d221aa917240f2774947029747730fe308db049b7b5f1ca175d877e83efd923";

    public function testGenerate(): void
    {
        $timestamp = 1721126075;
        $secret = "secret";
        $signature = Generator::generate(
            "/test",
            "",
            $secret,
            $timestamp
        );

        $this->assertEquals(self::RESULT, $signature);
        $this->assertNotEquals(self::RESULT_WITH_PAYLOAD, $signature);
    }

    public function testGenerateWithInvalidSecret(): void
    {
        $timestamp = 1721126075;
        $secret = "123";
        $signature = Generator::generate(
            "/test",
            "",
            $secret,
            $timestamp
        );

        $this->assertNotEquals(self::RESULT, $signature);
        $this->assertNotEquals(self::RESULT_WITH_PAYLOAD, $signature);
    }

    public function testGenerateWithInvalidTimestamp(): void
    {
        $secret = "123";
        $signature = Generator::generate(
            "/test",
            "",
            $secret
        );

        $this->assertNotEquals(self::RESULT, $signature);
        $this->assertNotEquals(self::RESULT_WITH_PAYLOAD, $signature);
    }

    public function testGenerateWithPayload(): void
    {
        $timestamp = 1721126075;
        $secret = "secret";
        $payload = '{"test": "123"}';
        $signature = Generator::generate(
            "/test",
            $payload,
            $secret,
            $timestamp
        );

        $this->assertEquals(self::RESULT_WITH_PAYLOAD, $signature);
        $this->assertNotEquals(self::RESULT, $signature);
    }
}