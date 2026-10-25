<?php

declare(strict_types=1);

namespace Tokenlore\Http;

// Name und Wert des Sitzungs-Cookies. Der Name ist __Host-tl_ plus die ersten 8 Hex-Zeichen von
// sha256(scriptBase): __Host- erzwingt Path=/ ohne Domain, der Name trennt zwei Installationen auf
// demselben Host. Kommt der Name in der Anfrage mehrfach vor (etwa ein untergeschobenes Cookie),
// gilt sie als nicht angemeldet.
final class SessionCookie
{
    public static function name(Request $r): string
    {
        return '__Host-tl_' . substr(hash('sha256', $r->scriptBase), 0, 8);
    }

    /** Wert des Sitzungs-Cookies; null, wenn es fehlt oder mehrfach vorkommt. Die Form prüft der Aufrufer. */
    public static function token(Request $r): ?string
    {
        $name = self::name($r);
        $found = null;
        // Roh aus dem Header: Request::cookies behält bei doppeltem Namen nur den ersten.
        foreach (explode(';', $r->header('cookie') ?? '') as $part) {
            $eq = strpos($part, '=');
            if ($eq === false || trim(substr($part, 0, $eq)) !== $name) {
                continue;
            }
            if ($found !== null) {
                return null;
            }
            $value = trim(substr($part, $eq + 1));
            if (strlen($value) >= 2 && $value[0] === '"' && str_ends_with($value, '"')) {
                $value = substr($value, 1, -1);
            }
            $found = $value;
        }
        return $found;
    }

    /** Setzt das Cookie für $maxAge Sekunden (0 löscht es). */
    public static function set(Response $response, Request $r, string $token, int $maxAge): Response
    {
        return $response->withCookie(self::name($r), $token, [
            'path' => '/', 'maxAge' => $maxAge, 'secure' => true, 'httpOnly' => true, 'sameSite' => 'Strict',
        ]);
    }
}
