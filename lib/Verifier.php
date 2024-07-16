<?php

namespace Olek\Signature;

class Verifier
{
    public const DEFAULT_TOLERANCE = 300;

    /**
     * @throws VerificationException
     */
    public static function verify(string $path, string $payload, string $header, string $secret, int $tolerance = self::DEFAULT_TOLERANCE): bool
    {
        $timestamp = self::getTimestamp($header);
        $signature = self::getSignatures($header);

        if (-1 === $timestamp) {
            throw new VerificationException("Unable to extract timestamp and signatures from header");
        }
        if (empty($signature)) {
            throw new VerificationException("No signatures found with expected scheme");
        }

        $expectedSignature = Generator::generate($path, $payload, $secret, $timestamp);
        $resultCompare = self::compare($expectedSignature, $signature);

        if ($resultCompare === false) {
            throw new VerificationException("No signatures found matching the expected signature for payload");
        }

        if (($tolerance > 0) && (abs(time() - $timestamp) > $tolerance)) {
            throw new VerificationException("Timestamp outside the tolerance zone");
        }

        return true;
    }

    private static function getTimestamp(string $header): int
    {
        $items = explode(',', $header);

        foreach ($items as $item) {
            $itemParts = explode('=', $item, 2);
            if ('t' === $itemParts[0]) {
                if (!is_numeric($itemParts[1])) {
                    return -1;
                }

                return (int) ($itemParts[1]);
            }
        }

        return -1;
    }

    private static function getSignatures(string $header)
    {
        $items = explode(',', $header);

        foreach ($items as $item) {
            $itemParts = explode('=', $item, 2);
            if ("s" === trim($itemParts[0])) {
                return $itemParts[1];
            }
        }

        return "";
    }

    private static function compare(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}