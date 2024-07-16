<?php

namespace Olek\Tests;

use Olek\Signature\Generator;
use Olek\Signature\VerificationException;
use Olek\Signature\Verifier;
use PHPUnit\Framework\TestCase;

class VerifierTest extends TestCase
{
    public function testVerifier1(): void
    {
        $path = "/test";
        $payload = "";
        $timestamp = 1721126075;
        $secret = "secret";
        $signature = Generator::generate($path, $payload, $secret, $timestamp);
        $result = Verifier::verifySignature($path, $payload, $signature, $secret, $timestamp);

        $this->assertTrue($result);
    }

    public function testVerifierException1(): void
    {
        $this->expectException(VerificationException::class);
        $path1 = "/test";
        $path2 = "/abs";
        $payload = "";
        $timestamp = 1721126075;
        $secret = "secret";
        $signature = Generator::generate($path1, $payload, $secret, $timestamp);
        Verifier::verifySignature($path2, $payload, $signature, $secret, $timestamp);
    }

    public function testVerifierException2(): void
    {
        $this->expectException(VerificationException::class);
        $path = "/test";
        $payload1 = "";
        $payload2 = '{"test": "123"}';
        $timestamp = 1721126075;
        $secret = "secret";
        $signature = Generator::generate($path, $payload1, $secret, $timestamp);
        Verifier::verifySignature($path, $payload2, $signature, $secret, $timestamp);
    }

    public function testVerifierException3(): void
    {
        $this->expectException(VerificationException::class);
        $path = "/test";
        $payload = "";
        $timestamp = 1721126075;
        $secret = "secret";
        $signature = Generator::generate($path, $payload, $secret, $timestamp);
        Verifier::verifySignature($path, $payload, $signature, $secret);
    }

    public function testVerifier2(): void
    {
        $path = "/test";
        $payload = "";
        $timestamp1 = 1721126075;
        $timestamp2 = 1721127075;
        $secret = "secret";
        $signature = Generator::generate($path, $payload, $secret, $timestamp1);
        $result = Verifier::verifySignature($path, $payload, $signature, $secret, $timestamp2);
        $this->assertTrue($result);
    }
}