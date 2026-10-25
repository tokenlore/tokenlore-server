<?php

declare(strict_types=1);

namespace Tokenlore\Config;

use Tokenlore\Http\Request;

// Öffentliche Adresse des Servers, wie sie im Kopplungsbefehl für das Plugin steht.
final class BaseUrl
{
    private const HOST = '/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::(\d{1,5}))?\z/';

    /**
     * Die gespeicherte öffentliche Adresse (Einstellung „public_url“) hat Vorrang; ohne sie gilt die erkannte.
     * Ohne Schrägstrich am Ende.
     */
    public static function effective(Request $r, ?string $storedUrl, bool $trustProxy): string
    {
        $stored = rtrim(trim($storedUrl ?? ''), '/');
        return $stored !== '' ? $stored : self::detect($r, $trustProxy);
    }

    /**
     * Ermittelt die Adresse aus Host, HTTPS-Erkennung und dem Pfad von index.php, z. B.
     * https://example.de/tokenlore, bei Aufruf über index.php/… mit …/tokenlore/index.php.
     * X-Forwarded-Proto und X-Forwarded-Host zählen nur mit trustProxy. Ein ungültiger Host
     * (Header-Einschleusung) ergibt localhost; die Adresse lässt sich in den Einstellungen korrigieren.
     */
    public static function detect(Request $r, bool $trustProxy): string
    {
        $https = $r->isHttps($trustProxy);
        $candidates = [$r->header('host') ?? ''];
        if ($trustProxy) {
            array_unshift($candidates, self::lastEntry($r->header('x-forwarded-host') ?? ''));
        }
        $host = 'localhost';
        foreach ($candidates as $candidate) {
            $candidate = strtolower(trim($candidate));
            if (preg_match(self::HOST, $candidate, $m) && (!isset($m[1]) || (int) $m[1] <= 65535)) {
                $host = $candidate;
                break;
            }
        }
        // Übliche Ports entfallen.
        $host = preg_replace($https ? '/:443\z/' : '/:80\z/', '', $host) ?? $host;
        return ($https ? 'https' : 'http') . '://' . $host . $r->scriptBase . ($r->viaIndexPhp ? '/index.php' : '');
    }

    private static function lastEntry(string $list): string
    {
        $i = strrpos($list, ',');
        return $i === false ? $list : substr($list, $i + 1);
    }
}
