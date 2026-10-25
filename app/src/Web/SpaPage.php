<?php

declare(strict_types=1);

namespace Tokenlore\Web;

use Tokenlore\Http\Kernel;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;

// Liefert die gebaute SvelteKit-Seite aus dem Installationsordner (Gegenstück zu internal/web/web.go):
// index.html mit CSP samt Hashes der Inline-Skripte, dazu notfalls _app/…, favicon.svg und theme-init.js.
// Im Normalfall liefert Apache die statischen Dateien selbst; hier landen nur Aufrufe über index.php/….
final class SpaPage
{
    // Typen ausdrücklich, unabhängig von der Mime-Zuordnung des Servers.
    private const TYPES = [
        'js' => 'text/javascript; charset=utf-8',
        'mjs' => 'text/javascript; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'html' => 'text/html; charset=utf-8',
        'svg' => 'image/svg+xml',
        'woff2' => 'font/woff2',
        'json' => 'application/json',
        'ico' => 'image/x-icon',
        'png' => 'image/png',
        'webmanifest' => 'application/manifest+json',
        'txt' => 'text/plain; charset=utf-8',
    ];

    // Ausführbare Skripttypen; alles andere (application/json, importmap …) sind Datenblöcke ohne Hash.
    private const JS_TYPES = [
        'application/javascript', 'application/ecmascript', 'application/x-javascript', 'application/x-ecmascript',
        'text/javascript', 'text/ecmascript', 'text/javascript1.0', 'text/javascript1.1', 'text/javascript1.2',
        'text/javascript1.3', 'text/javascript1.4', 'text/javascript1.5', 'text/jscript', 'text/livescript',
        'text/x-javascript', 'text/x-ecmascript',
    ];

    // Dateien im Wurzelordner, die ausgeliefert werden dürfen (zusätzlich alles unter _app/).
    private const ROOT_FILES = ['favicon.svg', 'theme-init.js'];

    /**
     * Die Startseite: $dir/index.html mit CSP (Grund-CSP des Kerns, script-src um die Hashes der Inline-Skripte
     * erweitert) und Cache-Control: no-cache. Fehlt die Datei oder steht darin ein style-Attribut oder <style>
     * (die CSP bleibt ohne unsafe-inline), wirft sie eine RuntimeException.
     */
    public static function render(string $dir): Response
    {
        $file = $dir . '/index.html';
        $html = is_file($file) ? file_get_contents($file) : false;
        if ($html === false) {
            throw new \RuntimeException('Webseite prüfen: index.html fehlt in ' . $dir);
        }
        $hashes = self::scriptHashes($html);
        $csp = Kernel::CSP;
        if ($hashes !== []) {
            $csp = str_replace("script-src 'self'", "script-src 'self' '" . implode("' '", $hashes) . "'", $csp);
        }
        return self::file(hash('sha256', $html, true), 'html', 'no-cache', $html)->withHeader('Content-Security-Policy', $csp);
    }

    /**
     * Eine erlaubte statische Datei oder null. Erlaubt sind nur favicon.svg, theme-init.js und Dateien unter
     * _app/ (Pfad relativ zum Installationsordner, ohne führenden Schrägstrich); versteckte Segmente (".…"),
     * "..", leere Segmente, Backslash, Doppelpunkt und Steuerzeichen werden abgelehnt, ebenso Symlinks, die aus
     * dem erlaubten Bereich hinausführen. Unter _app/immutable/ steht der Dateiname mit Hash, dort gilt ein
     * Jahr Cache, sonst no-cache.
     */
    public static function asset(string $dir, string $name): ?Response
    {
        if (!self::allowedName($name)) {
            return null;
        }
        $file = $dir . '/' . $name;
        $root = realpath($dir);
        if ($root === false || !is_file($file) || ($real = realpath($file)) === false) {
            return null;
        }
        if (str_starts_with($name, '_app/')) {
            $app = realpath($dir . '/_app');
            if ($app === false || !str_starts_with($real, $app . DIRECTORY_SEPARATOR)) {
                return null;
            }
        } elseif ($real !== $root . DIRECTORY_SEPARATOR . $name) {
            return null;
        }
        // Den ETag rechnet hash_file stückweise; die Datei selbst gibt Response::send mit readfile aus. So liegt auch
        // eine große Datei (Schrift, Bundle) nie ganz im Speicher.
        $hash = @hash_file('sha256', $real, true);
        if ($hash === false) {
            return null;
        }
        $cache = str_starts_with($name, '_app/immutable/') ? 'public, max-age=31536000, immutable' : 'no-cache';
        return self::file($hash, strtolower(pathinfo($name, PATHINFO_EXTENSION)), $cache, '', $real);
    }

    /** Antwortet auf If-None-Match mit 304 (ohne Inhalt), wenn der ETag der Seite passt; sonst bleibt die Antwort. */
    public static function revalidate(Request $request, Response $page): Response
    {
        $etag = $page->header('ETag');
        $sent = $request->header('If-None-Match');
        if ($page->status !== 200 || $etag === null || $sent === null || !self::etagMatches($sent, $etag)) {
            return $page;
        }
        $r = new Response(304);
        foreach ($page->headerLines() as $name => $value) {
            if (strtolower($name) !== 'content-type') {
                $r = $r->withHeader($name, $value);
            }
        }
        return $r;
    }

    /**
     * Sortierte, eindeutige CSP-Hashes ("sha256-…") aller ausführbaren <script> ohne src. Datenblöcke
     * (type="application/json") brauchen keinen Hash. Wirft bei <style>, style-Attribut und <script>
     * ohne schließendes Tag. Liest HTML wie der Browser: Kommentare, Anführungszeichen in Attributen.
     *
     * @return list<string>
     */
    public static function scriptHashes(string $b): array
    {
        $n = strlen($b);
        $set = [];
        $i = 0;
        while ($i < $n) {
            $lt = strpos($b, '<', $i);
            if ($lt === false) {
                break;
            }
            $i = $lt;
            if (substr($b, $i, 4) === '<!--') {
                $i = self::skipComment($b, $i + 4);
                continue;
            }
            if ($i + 1 >= $n || !self::isAlpha($b[$i + 1])) {
                $i++;
                continue;
            }
            $j = $i + 1;
            while ($j < $n && !self::isSpace($b[$j]) && $b[$j] !== '>' && $b[$j] !== '/') {
                $j++;
            }
            $tag = strtolower(substr($b, $i + 1, $j - $i - 1));
            $hasSrc = false;
            $type = '';
            // Attribute bis zum schließenden '>' (Anführungszeichen beachten).
            while ($j < $n && $b[$j] !== '>') {
                while ($j < $n && (self::isSpace($b[$j]) || $b[$j] === '/')) {
                    $j++;
                }
                $s = $j;
                while ($j < $n && !self::isSpace($b[$j]) && $b[$j] !== '=' && $b[$j] !== '>' && $b[$j] !== '/') {
                    $j++;
                }
                $attr = strtolower(substr($b, $s, $j - $s));
                while ($j < $n && self::isSpace($b[$j])) {
                    $j++;
                }
                $val = '';
                if ($j < $n && $b[$j] === '=') {
                    $j++;
                    while ($j < $n && self::isSpace($b[$j])) {
                        $j++;
                    }
                    if ($j < $n && ($b[$j] === '"' || $b[$j] === "'")) {
                        $end = strpos($b, $b[$j], $j + 1);
                        $end = $end === false ? $n : $end;
                        $val = substr($b, $j + 1, $end - $j - 1);
                        $j = $end + 1;
                    } else {
                        $vs = $j;
                        while ($j < $n && !self::isSpace($b[$j]) && $b[$j] !== '>') {
                            $j++;
                        }
                        $val = substr($b, $vs, $j - $vs);
                    }
                }
                if ($attr === 'style') {
                    throw new \RuntimeException('style-Attribut im HTML nicht erlaubt (CSP ohne unsafe-inline)');
                }
                if ($attr === 'src') {
                    $hasSrc = $hasSrc || $tag === 'script';
                } elseif ($attr === 'type') {
                    $type = $val;
                }
            }
            $j = min($j + 1, $n); // '>'
            if ($tag === 'style') {
                throw new \RuntimeException('<style> im HTML nicht erlaubt (CSP ohne unsafe-inline)');
            }
            if ($tag === 'script') {
                $end = stripos($b, '</script', $j);
                if ($end === false) {
                    throw new \RuntimeException('<script> ohne schließendes Tag');
                }
                if (!$hasSrc && self::executable($type)) {
                    $set['sha256-' . base64_encode(hash('sha256', substr($b, $j, $end - $j), true))] = true;
                }
                $j = $end;
            }
            $i = $j;
        }
        $out = array_keys($set);
        sort($out, SORT_STRING);
        return $out;
    }

    /** $hash: SHA-256 des Inhalts (rohe Bytes); $body im Speicher oder $path einer Datei, die Response ausgibt. */
    private static function file(string $hash, string $ext, string $cache, string $body = '', ?string $path = null): Response
    {
        $etag = '"' . rtrim(strtr(base64_encode(substr($hash, 0, 16)), '+/', '-_'), '=') . '"';
        return (new Response(200, $body, $path))
            ->withHeader('ETag', $etag)
            ->withHeader('Content-Type', self::TYPES[$ext] ?? 'application/octet-stream')
            ->withHeader('Cache-Control', $cache);
    }

    private static function allowedName(string $name): bool
    {
        if (!in_array($name, self::ROOT_FILES, true) && !str_starts_with($name, '_app/')) {
            return false;
        }
        // Steuerzeichen (auch NUL), Backslash und Doppelpunkt (Laufwerk, NTFS-Stream) kommen in keiner Datei vor.
        if (preg_match('/[\x00-\x1F\x7F\\\\:]/', $name) === 1) {
            return false;
        }
        foreach (explode('/', $name) as $segment) {
            if ($segment === '' || $segment[0] === '.') { // leer, ".", ".." und versteckte Dateien
                return false;
            }
        }
        return true;
    }

    private static function etagMatches(string $ifNoneMatch, string $etag): bool
    {
        foreach (explode(',', $ifNoneMatch) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate === '*' || (str_starts_with($candidate, 'W/') ? substr($candidate, 2) : $candidate) === $etag) {
                return true;
            }
        }
        return false;
    }

    /**
     * Stelle hinter dem Kommentar, dessen Inhalt bei $i beginnt. Wie der Browser: "<!-->" und "<!--->" sind leere
     * Kommentare, "--!>" schließt ebenfalls; ein offener Kommentar reicht bis zum Ende.
     */
    private static function skipComment(string $b, int $i): int
    {
        if (substr($b, $i, 1) === '>') {
            return $i + 1;
        }
        if (substr($b, $i, 2) === '->') {
            return $i + 2;
        }
        $e1 = strpos($b, '-->', $i);
        $e2 = strpos($b, '--!>', $i);
        if ($e1 !== false && ($e2 === false || $e1 < $e2)) {
            return $e1 + 3;
        }
        return $e2 !== false ? $e2 + 4 : strlen($b);
    }

    // Nur ausführbare Skripte werden gehasht: ohne type, leer, module oder JavaScript-MIME-Typ.
    private static function executable(string $type): bool
    {
        $t = strtolower(trim($type, " \t\n\r\f"));
        return $t === '' || $t === 'module' || in_array($t, self::JS_TYPES, true);
    }

    private static function isAlpha(string $c): bool
    {
        return ($c >= 'a' && $c <= 'z') || ($c >= 'A' && $c <= 'Z');
    }

    private static function isSpace(string $c): bool
    {
        return $c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" || $c === "\f";
    }
}
