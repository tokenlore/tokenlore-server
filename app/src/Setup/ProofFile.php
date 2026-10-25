<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

// Eine Datei, die jemand per FTP in den Datenordner legt, als Nachweis, dass er den Server besitzt
// (Notfall-Zugang: reset-admin.txt, Einrichtung: setup-code.txt). Sie muss genau einen erwarteten Code enthalten.
final class ProofFile
{
    /** Mehr wird von der Datei nie gelesen. */
    public const MAX_BYTES = 1024;
    /** Spielraum für eine Datei, deren Zeitstempel (Uhr des FTP-Programms) etwas vorgeht. */
    private const FUTURE_SKEW = 300;

    /**
     * Die Datei ist ein reguläres File (kein Symlink, kein Ordner), höchstens MAX_BYTES groß, jünger als
     * $ttl Sekunden und enthält genau $code (Leerraum und ein UTF-8-BOM am Rand zählen nicht). Verglichen wird in
     * konstanter Zeit über die Hashes.
     */
    public static function matches(string $path, string $code, int $now, int $ttl): bool
    {
        $st = self::regularFile($path);
        if ($st === null || $st['size'] > self::MAX_BYTES || $st['mtime'] > $now + self::FUTURE_SKEW) {
            return false;
        }
        if ($now - $st['mtime'] >= $ttl) {
            return false;
        }
        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            return false;
        }
        try {
            // Dieselbe Datei wie geprüft (nicht zwischendurch gegen einen Symlink oder etwas anderes getauscht).
            $opened = fstat($fh);
            if ($opened === false || ($opened['mode'] & 0170000) !== 0100000
                || $opened['ino'] !== $st['ino'] || $opened['dev'] !== $st['dev']) {
                return false;
            }
            $data = fread($fh, self::MAX_BYTES + 1);
        } finally {
            fclose($fh);
        }
        if ($data === false || strlen($data) > self::MAX_BYTES) {
            return false;
        }
        $data = trim($data);
        if (str_starts_with($data, "\xEF\xBB\xBF")) {
            $data = trim(substr($data, 3));
        }
        return hash_equals(hash('sha256', $data), hash('sha256', $code));
    }

    /** true, wenn die Datei ein reguläres File ist, das älter als $ttl Sekunden ist. */
    public static function stale(string $path, int $now, int $ttl): bool
    {
        $st = self::regularFile($path);
        return $st !== null && $now - $st['mtime'] >= $ttl;
    }

    /** Löscht die Datei, wenn sie ein reguläres File ist; ein Symlink oder sein Ziel bleiben unberührt. */
    public static function remove(string $path): void
    {
        if (self::regularFile($path) !== null) {
            @unlink($path);
        }
    }

    /**
     * lstat der Datei, wenn sie ein reguläres File und kein Symlink ist; sonst null.
     *
     * @return array<string,int>|null
     */
    private static function regularFile(string $path): ?array
    {
        clearstatcache(true, $path);
        if (is_link($path)) {
            return null;
        }
        $st = @lstat($path);
        if ($st === false || ($st['mode'] & 0170000) !== 0100000) {
            return null;
        }
        return $st;
    }
}
