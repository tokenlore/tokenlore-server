<?php

declare(strict_types=1);

namespace Tokenlore\RateLimit;

// Einordnung von IP-Adressen (öffentlich oder reserviert), neben IpKey, das die Adressen normalisiert.
// Genutzt für den Proxy-Vorschlag der Einrichtung (Setup::proxySuggested).
final class Network
{
    // Nicht öffentliche Bereiche (RFC 6890 u. a.), unabhängig von den Filter-Flags der PHP-Version.
    private const BLOCKED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        '::/128', '::1/128', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32',
        '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
    ];

    private function __construct()
    {
    }

    /** true nur für Adressen im öffentlichen Internet; alles Unlesbare und jeder reservierte Bereich ist false. */
    public static function isPublicAddress(string $ip): bool
    {
        $normal = IpKey::normalize($ip);
        $packed = $normal === null ? false : inet_pton($normal);
        if ($packed === false) {
            return false;
        }
        foreach (self::BLOCKED as $block) {
            [$net, $bits] = explode('/', $block);
            $netPacked = inet_pton($net);
            if ($netPacked !== false && strlen($netPacked) === strlen($packed) && self::samePrefix($packed, $netPacked, (int) $bits)) {
                return false;
            }
        }
        return true;
    }

    private static function samePrefix(string $a, string $b, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
    }
}
