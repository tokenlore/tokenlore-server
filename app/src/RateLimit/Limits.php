<?php

declare(strict_types=1);

namespace Tokenlore\RateLimit;

// Die Grenzen der Routen, Werte wie ratelimit.Config.WithDefaults im Go-Server.
// *_PER_* ist die Rate in Anfragen je Sekunde, *_BURST die Menge, die auf einmal durchgeht.
// MaxLogins/LoginWait des Go-Servers (gleichzeitige Passwortprüfungen) sind keine Ratengrenzen
// und stehen hier nicht.
final class Limits
{
    // Ingest: je Gerät und je IP (die IP-Grenze greift vor der Authentifizierung).
    public const INGEST_PER_KEY = 10.0;
    public const INGEST_PER_KEY_BURST = 20;
    public const INGEST_PER_IP = 20.0;
    public const INGEST_PER_IP_BURST = 40;

    // Login und Pair: je IP 1 Versuch alle 6 s (10 je Minute), Burst 5.
    public const LOGIN_PER_IP = 1.0 / 6.0;
    public const LOGIN_BURST = 5;
    public const PAIR_PER_IP = 1.0 / 6.0;
    public const PAIR_BURST = 5;

    // Notfall-Zugang (start und finish): wie Login, aber ein eigener Topf (Bucket), damit Recovery-Spam die
    // Anmeldung nicht sperrt und umgekehrt.
    public const RECOVERY_PER_IP = 1.0 / 6.0;
    public const RECOVERY_BURST = 5;

    // Abruf des öffentlichen CA-Zertifikats (ohne Anmeldung): je IP 1 alle 2 s (30 je Minute), Burst 10.
    public const CA_PER_IP = 0.5;
    public const CA_BURST = 10;

    // Abruf der Server-Kennung vor dem Koppeln (ohne Anmeldung): wie der CA-Abruf, eigener Topf.
    public const INFO_PER_IP = 0.5;
    public const INFO_BURST = 10;

    // Alle Sitzungsrouten je IP, vor der Sitzungsprüfung.
    public const SESSION_PER_IP = 20.0;
    public const SESSION_BURST = 60;

    // Rate und Burst der IPv6-/48-Sammelgrenze gegenüber der Grenze je /64 (ratelimit.AggregateFactor).
    public const AGGREGATE_FACTOR = 16;

    // Grenzen je Client-IP für Http\Middleware::limitIp: Name => [Rate je Sekunde, Burst].
    public const PER_IP = [
        'login' => [self::LOGIN_PER_IP, self::LOGIN_BURST],
        'pair' => [self::PAIR_PER_IP, self::PAIR_BURST],
        'recovery' => [self::RECOVERY_PER_IP, self::RECOVERY_BURST],
        'ca' => [self::CA_PER_IP, self::CA_BURST],
        'info' => [self::INFO_PER_IP, self::INFO_BURST],
        'session' => [self::SESSION_PER_IP, self::SESSION_BURST],
        'ingest_ip' => [self::INGEST_PER_IP, self::INGEST_PER_IP_BURST],
    ];

    // Rundungsspielraum: 1 / (1/6) ergibt in Gleitkomma knapp über 6.
    private const EPSILON = 1e-9;

    private function __construct()
    {
    }

    /**
     * Wartezeit bis zum nächsten Token in ganzen Sekunden, mindestens 1, für den Retry-After-Header
     * der 429-Antwort (wie RetryAfter im Go-Server: aus der Rate, nicht aus dem Füllstand).
     */
    public static function retryAfter(float $perSecond): int
    {
        if (!is_finite($perSecond) || $perSecond <= 0) {
            return 1;
        }
        return max(1, (int) ceil(1.0 / $perSecond - self::EPSILON));
    }
}
