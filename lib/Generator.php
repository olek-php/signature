<?php

namespace Olek\Signature;

class Generator
{
    public static function generate(string $path, string $payload, string $secret, ?int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        $signedPayload = "$timestamp.$path.$payload";
        $data = [
            "t" => $timestamp,
            "s" => self::compute($signedPayload, $secret)
        ];
        return implode(",", array_map(function ($v, $k) {
            return sprintf("%s=%s", $k, $v);
        }, $data, array_keys($data)));
    }

    private static function compute(string $payload, string $secret): string
    {
        return hash_hmac("sha512", $payload, $secret);
    }
}