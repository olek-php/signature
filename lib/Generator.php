<?php

namespace Olek\Signature;

class Generator
{
    public static function generate(string $path, string $payload, string $secret, ?int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        $signedPayload = "$timestamp.$path.$payload";
        return self::compute($signedPayload, $secret);
    }

    private static function compute(string $payload, string $secret): string
    {
        return hash_hmac("sha512", $payload, $secret);
    }
}