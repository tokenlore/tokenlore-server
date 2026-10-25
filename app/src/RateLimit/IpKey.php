<?php

declare(strict_types=1);

namespace Tokenlore\RateLimit;

// Schlüssel einer Client-IP für die Ratengrenzen (wie limitKey, aggregateKey und normalizeAddr in
// internal/httpapi/clientip.go). Die einzige Stelle, an der IP-Adressen gekürzt werden.
//
// Jede Methode normalisiert selbst, auch wenn Request::clientIp das schon getan hat: Zone (%eth0)
// weg, IPv4-in-IPv6 (::ffff:a.b.c.d) wird IPv4 (wie Go WithZone("").Unmap()). Sonst landeten alle
// IPv4-Adressen hinter einem Dual-Stack-Socket im selben „/64“ (::/64).
final class IpKey
{
    private function __construct()
    {
    }

    // Normalform der Adresse (auch für Request::clientIp); null für Unlesbares.
    public static function normalize(string $ip): ?string
    {
        $packed = self::pack($ip);
        return $packed === null ? null : self::text($packed);
    }

    // Schlüssel je IP: IPv4 voll, IPv6 auf das /64-Präfix gekürzt (Rotation im eigenen Präfix bringt
    // nichts), z. B. "2001:db8:1:2::/64". Unlesbares bleibt unverändert.
    public static function perIp(string $ip): string
    {
        $packed = self::pack($ip);
        if ($packed === null) {
            return $ip;
        }
        return strlen($packed) === 16 ? self::prefix($packed, 64) : self::text($packed);
    }

    // Schlüssel der Sammelgrenze: das /48-Präfix einer IPv6-Adresse; IPv4 hat keine zweite Stufe (null).
    public static function aggregate(string $ip): ?string
    {
        $packed = self::pack($ip);
        return $packed !== null && strlen($packed) === 16 ? self::prefix($packed, 48) : null;
    }

    // Binärform (4 oder 16 Bytes) ohne Zone, IPv4-in-IPv6 als IPv4; null für Unlesbares.
    private static function pack(string $ip): ?string
    {
        $ip = explode('%', $ip, 2)[0];
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $packed = inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
            $packed = substr($packed, 12);
        }
        return $packed;
    }

    private static function prefix(string $packed, int $bits): string
    {
        $keep = intdiv($bits, 8);
        return self::text(substr($packed, 0, $keep) . str_repeat("\0", 16 - $keep)) . '/' . $bits;
    }

    private static function text(string $packed): string
    {
        $text = inet_ntop($packed);
        if ($text === false) {
            throw new \LogicException('inet_ntop scheitert an einer gültigen Adresse.');
        }
        return $text;
    }
}
