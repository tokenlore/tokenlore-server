<?php

declare(strict_types=1);

namespace Tokenlore\Auth;

// Passwort-Hashes mit Argon2id im PHC-Format, Parameter wie internal/auth/password.go
// (64 MiB, 3 Durchläufe, 2 Threads, 16 Byte Salz, 32 Byte Schlüssel). Hashes des Go-Servers bleiben gültig.
final class Password
{
    private const MEMORY_KIB = 65536;
    private const TIME = 3;
    private const THREADS = 2;

    public static function hash(string $pw): string
    {
        // Mit libsodium als Grundlage kennt PHP nur einen Thread; das Ergebnis bleibt Argon2id mit p=1.
        $threads = PASSWORD_ARGON2_PROVIDER === 'standard' ? self::THREADS : 1;
        return password_hash($pw, PASSWORD_ARGON2ID, [
            'memory_cost' => self::MEMORY_KIB,
            'time_cost' => self::TIME,
            'threads' => $threads,
        ]);
    }

    /**
     * Prüft $pw gegen einen Argon2id-Hash; die Parameter kommen aus dem Hash selbst. Fremde Formate
     * und Parameter außerhalb der Grenzen (Schutz vor manipulierten Hashes) ergeben false.
     */
    public static function verify(string $hash, string $pw): bool
    {
        if (!preg_match('/^\$argon2id\$v=19\$m=(\d{1,7}),t=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+\/]+)\$([A-Za-z0-9+\/]+)\z/', $hash, $m)) {
            return false;
        }
        [$mem, $time, $threads] = [(int) $m[1], (int) $m[2], (int) $m[3]];
        if ($mem === 0 || $mem > 1 << 20 || $time === 0 || $time > 20 || $threads === 0 || $threads > 32) {
            return false;
        }
        // Base64 ohne Auffüllung: 4 Zeichen sind 3 Bytes. Schlüssel 16 bis 64 Bytes wie im Go-Server.
        $keyLen = intdiv(strlen($m[5]) * 3, 4);
        if ($keyLen < 16 || $keyLen > 64) {
            return false;
        }
        return password_verify($pw, $hash);
    }
}
