<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

use stdClass;
use Tokenlore\Protocol\Limits;
use Tokenlore\Protocol\Validator;

// Liest und prüft Lieferpakete wie internal/ingest/decode.go und validate.go: gleiche Reihenfolge der Prüfungen,
// gleiche Pfade und Meldungen. Fehler nennen nur den Feldpfad und was daran falsch ist, nie den Wert.
//
// JSON wird mit Objekten statt assoziativen Arrays dekodiert. Nur so bleiben {} und [] unterscheidbar, und ein
// Objekt mit den Schlüsseln "0", "1" (z. B. Werkzeuge namens "0") wird nicht für eine Liste gehalten. Go lehnt
// Listen an Stellen für Objekte ab und nimmt solche Objekte an; der Dekodierer tut dasselbe, ohne den Rohtext
// selbst zu zerlegen. Danach kommen die Daten als Arrays in festen Formen heraus (siehe decode()).
final class Decoder
{
    /** Protokollversion, die jede Lieferung trägt (protocol.Version). */
    public const VERSION = 1;

    public const TYPE_ERROR = Validator::TYPE_ERROR;

    // Kontenliste: Grenze vor dem Dekodieren der Elemente (maxAccounts in decode.go).
    private const MAX_ACCOUNTS = 1000;

    // Höchste Schachtelungstiefe; Gos Dekodierer bricht ab 10.000 Ebenen mit einem Syntaxfehler ab.
    private const MAX_DEPTH = 10_000;

    private const WS = " \t\n\r";

    // Felder der Strukturen aus https://github.com/tokenlore/tokenlore/blob/main/protocol/protocol.go mit ihrem Typ.
    private const DEVICE = ['os' => 'string', 'arch' => 'string', 'tz' => 'string', 'plugin_version' => 'string'];
    private const ACCOUNT = ['account_id' => 'string', 'email_mode' => 'string', 'email' => 'string'];
    private const SESSION = ['session_id' => 'string', 'project_id' => 'string', 'cc_version' => 'string', 'account_id' => 'string'];
    private const REQUEST = [
        'request_id' => 'string', 'message_id' => 'string', 'session_id' => 'string', 'ts' => 'time',
        'utc_offset_min' => 'int', 'model' => 'string',
        'input' => 'int', 'output' => 'int', 'cache_create' => 'int', 'cache_read' => 'int',
        'cache_1h' => 'int', 'cache_5m' => 'int', 'thinking' => 'int', 'web_search' => 'int', 'web_fetch' => 'int',
        'stop_reason' => 'string', 'subagent' => 'bool', 'tools' => 'intmap', 'account_id' => 'string', 'extra' => 'anymap',
    ];
    private const LEGACY_MODEL = ['date' => 'string', 'model' => 'string', 'tokens' => 'int'];
    private const LEGACY_ACTIVITY = ['date' => 'string', 'messages' => 'int', 'sessions' => 'int', 'tool_calls' => 'int'];

    // Listen in der Reihenfolge, in der Go ihre Elemente dekodiert.
    private const LISTS = [
        'accounts' => self::ACCOUNT,
        'sessions' => self::SESSION,
        'requests' => self::REQUEST,
        'legacy_model' => self::LEGACY_MODEL,
        'legacy_activity' => self::LEGACY_ACTIVITY,
    ];

    // Listengrenzen in der Reihenfolge, in der Go sie vor den Elementen prüft.
    private const LIST_LIMITS = [
        'requests' => Limits::MAX_REQUESTS_PER_BATCH,
        'legacy_model' => Limits::MAX_LEGACY_LIST,
        'legacy_activity' => Limits::MAX_LEGACY_LIST,
        'accounts' => self::MAX_ACCOUNTS,
        'sessions' => Limits::MAX_SESSIONS_PER_BATCH,
    ];

    // Nullzeit (0001-01-01T00:00:00Z) in Millisekunden, wie ein fehlendes ts in Go.
    private const ZERO_TIME_MS = -62_135_596_800_000;

    /**
     * Liest genau ein Paket-Objekt. Unbekannte Felder, falsche Typen und Text nach dem Objekt sind Fehler.
     * Feldnamen passen wie in Go auch ohne Beachtung der Groß-/Kleinschreibung; null gilt als Nullwert.
     * Ergebnis: v, device (os, arch, tz, plugin_version) und die Listen accounts, sessions, requests, legacy_model,
     * legacy_activity, jedes Element mit allen Feldern ("", 0, false, []). Anfragen tragen zusätzlich ts_ms
     * (Millisekunden seit 1970, UTC); ts bleibt der gelieferte Text für die Prüfung. Die Rumpfgrenze setzt der Aufrufer.
     *
     * @return array<string, mixed>
     * @throws IngestError
     */
    public static function decode(string $body): array
    {
        $end = self::firstValueEnd($body);
        if ($end === null) {
            throw new IngestError('', 'kein gültiges JSON');
        }
        try {
            $top = json_decode(substr($body, 0, $end), false, self::MAX_DEPTH, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (\JsonException) {
            throw new IngestError('', 'kein gültiges JSON');
        }
        if ($top === null) {
            throw new IngestError('', 'Paket ist kein JSON-Objekt');
        }
        if (!$top instanceof stdClass) {
            throw new IngestError('', self::TYPE_ERROR);
        }

        // Erste Stufe: Listen bleiben unzerlegt, damit ihre Länge vor den Elementen geprüft wird. Wie Go merkt sich
        // der Durchlauf den ersten Fehler in Dokumentreihenfolge; ein Listenfehler (Gos UnmarshalJSON) bricht sofort ab.
        $batch = ['v' => 0, 'device' => self::zero(self::DEVICE)];
        $raw = [];
        $saved = null;
        foreach (get_object_vars($top) as $key => $value) {
            $name = strtolower((string) $key);
            if ($name === 'v') {
                if (is_int($value)) {
                    $batch['v'] = $value;
                } elseif ($value !== null) {
                    $saved ??= new IngestError('v', self::TYPE_ERROR);
                }
            } elseif ($name === 'device') {
                if ($value instanceof stdClass) {
                    $batch['device'] = self::struct($value, self::DEVICE, 'device', '', $saved, $batch['device']);
                } elseif ($value !== null) {
                    $saved ??= new IngestError('device', self::TYPE_ERROR);
                }
            } elseif (isset(self::LISTS[$name])) {
                if ($value !== null && !is_array($value)) {
                    throw new IngestError($name, self::TYPE_ERROR);
                }
                $raw[$name] = $value ?? [];
            } else {
                // Den Namen aus der Eingabe nie wiederholen.
                $saved ??= new IngestError('', 'unbekanntes Feld');
            }
        }
        unset($top);
        if ($saved !== null) {
            throw $saved;
        }
        // Nach dem Objekt darf nur Leerraum folgen.
        if (strspn($body, self::WS, $end) !== strlen($body) - $end) {
            throw new IngestError('', 'Text nach dem JSON-Objekt');
        }
        foreach (self::LIST_LIMITS as $name => $max) {
            if (count($raw[$name] ?? []) > $max) {
                throw new IngestError($name, "mehr als $max Einträge");
            }
        }

        // Zweite Stufe: jedes Element streng für sich.
        foreach (self::LISTS as $name => $spec) {
            $out = [];
            foreach ($raw[$name] ?? [] as $i => $el) {
                $path = $name . '[' . $i . ']';
                $item = self::zero($spec);
                if ($el !== null) {
                    if (!$el instanceof stdClass) {
                        throw new IngestError($path, self::TYPE_ERROR);
                    }
                    $saved = null;
                    $item = self::struct($el, $spec, $path, $path, $saved, $item);
                    if ($saved !== null) {
                        throw $saved;
                    }
                }
                $out[] = $item;
            }
            unset($raw[$name]);
            $batch[$name] = $out;
        }
        return $batch;
    }

    /**
     * Prüft ein dekodiertes Paket und wirft den ersten Fehler. Jedes Element geht durch dieselbe Regel wie beim
     * Plugin (Protocol\Validator); hier wird nur der genaue Pfad bestimmt (Validate in validate.go).
     *
     * @param array<string, mixed> $b Ergebnis von decode()
     * @param int $nowMs Uhr des Servers in Millisekunden
     * @throws IngestError
     */
    public static function validate(array $b, int $nowMs): void
    {
        if ($b['v'] !== self::VERSION) {
            throw new IngestError('v', 'Protokollversion nicht unterstützt');
        }
        $err = Validator::device($b['device']);
        if ($err !== null) {
            throw self::fieldError('', $err, ['device.os', 'device.arch', 'device.tz', 'device.plugin_version']);
        }
        foreach ($b['accounts'] as $i => $a) {
            // "Adresse …"-Fehler gelten dem ganzen Konto; die Adresse selbst kommt nie in die Meldung.
            $err = Validator::account($a);
            if ($err !== null) {
                throw self::fieldError("accounts[$i]", $err, ['account_id', 'email_mode']);
            }
        }
        if (count($b['sessions']) > Limits::MAX_SESSIONS_PER_BATCH) {
            throw new IngestError('sessions', 'mehr als ' . Limits::MAX_SESSIONS_PER_BATCH . ' Einträge');
        }
        foreach ($b['sessions'] as $i => $s) {
            $err = Validator::session($s);
            if ($err !== null) {
                throw self::fieldError("sessions[$i]", $err, ['session_id', 'project_id', 'cc_version', 'account_id']);
            }
        }
        if (count($b['requests']) > Limits::MAX_REQUESTS_PER_BATCH) {
            throw new IngestError('requests', 'mehr als ' . Limits::MAX_REQUESTS_PER_BATCH . ' Anfragen');
        }
        foreach ($b['requests'] as $i => $r) {
            $err = Validator::request(self::forValidator($r), $nowMs);
            if ($err !== null) {
                throw self::requestError("requests[$i]", $r, $err);
            }
        }
        foreach (['legacy_model', 'legacy_activity'] as $list) {
            if (count($b[$list]) > Limits::MAX_LEGACY_LIST) {
                throw new IngestError($list, 'mehr als ' . Limits::MAX_LEGACY_LIST . ' Einträge');
            }
        }
        foreach ($b['legacy_model'] as $i => $d) {
            $err = Validator::legacyModel($d, $nowMs);
            if ($err !== null) {
                throw self::fieldError("legacy_model[$i]", $err, ['date', 'model', 'tokens']);
            }
        }
        foreach ($b['legacy_activity'] as $i => $d) {
            $err = Validator::legacyActivity($d, $nowMs);
            if ($err !== null) {
                throw self::fieldError("legacy_activity[$i]", $err, ['date', 'messages', 'sessions', 'tool_calls']);
            }
        }
    }

    /**
     * Dekodiert ein Objekt in die Felder von $spec (wie encoding/json in eine Struktur). Unbekannte Felder und
     * Typfehler merkt sich $saved (nur der erste zählt); ein ungültiges ts bricht sofort ab, weil Gos
     * time.Time.UnmarshalJSON seinen Fehler direkt zurückgibt ("Paket nicht lesbar").
     *
     * @param array<string, string> $spec
     * @param array<string, mixed> $into Nullwerte bzw. bisheriger Stand
     * @return array<string, mixed>
     */
    private static function struct(stdClass $o, array $spec, string $typePrefix, string $path, ?IngestError &$saved, array $into): array
    {
        foreach (get_object_vars($o) as $key => $v) {
            $field = strtolower((string) $key);
            $type = $spec[$field] ?? null;
            if ($type === null) {
                $saved ??= new IngestError($path, 'unbekanntes Feld');
                continue;
            }
            if ($type === 'time') {
                if ($v === null) {
                    continue;
                }
                $ms = is_string($v) ? self::parseTimestamp($v) : null;
                if ($ms === null) {
                    throw new IngestError($path, 'Paket nicht lesbar');
                }
                $into['ts'] = $v;
                $into['ts_ms'] = $ms;
                continue;
            }
            if ($v === null) {
                // null lässt Text, Zahl und Wahrheitswert unverändert und leert eine Map.
                if ($type === 'intmap' || $type === 'anymap') {
                    $into[$field] = [];
                }
                continue;
            }
            $ok = match ($type) {
                'string' => is_string($v),
                'int' => is_int($v),
                'bool' => is_bool($v),
                'intmap', 'anymap' => $v instanceof stdClass,
            };
            if ($ok && $type === 'intmap') {
                $map = [];
                foreach (get_object_vars($v) as $name => $n) {
                    if ($n !== null && !is_int($n)) {
                        $ok = false;
                        break;
                    }
                    $map[$name] = $n ?? 0;
                }
                $v = $map;
            } elseif ($ok && $type === 'anymap') {
                $v = get_object_vars($v);
            }
            if (!$ok) {
                // Pfad endet bei tools und extra: ihre Schlüssel stammen aus der Eingabe (safePath).
                $saved ??= new IngestError($typePrefix . '.' . $field, self::TYPE_ERROR);
                continue;
            }
            // Eine Map wird wie in Go ergänzt, nicht ersetzt, wenn das Feld doppelt vorkommt.
            $into[$field] = is_array($v) ? array_replace($into[$field], $v) : $v;
        }
        return $into;
    }

    /** @param array<string, string> $spec @return array<string, mixed> */
    private static function zero(array $spec): array
    {
        $out = [];
        foreach ($spec as $field => $type) {
            if ($type === 'time') {
                $out['ts'] = null;
                $out['ts_ms'] = self::ZERO_TIME_MS;
                continue;
            }
            $out[$field] = match ($type) {
                'string' => '',
                'int' => 0,
                'bool' => false,
                'intmap', 'anymap' => [],
            };
        }
        return $out;
    }

    /**
     * Validator erkennt Objekte an Arrays, die keine Liste sind. Werkzeuge oder extra mit den Schlüsseln "0", "1", …
     * sind nach dem Dekodieren aber eine Liste. Für die Prüfung bekommen sie deshalb Ersatznamen; Ziffern sind
     * gültige Werkzeug- und extra-Namen, das Prüfergebnis bleibt also gleich.
     *
     * @param array<string, mixed> $r
     * @return array<string, mixed>
     */
    private static function forValidator(array $r): array
    {
        foreach (['tools' => 't', 'extra' => 'k'] as $field => $prefix) {
            if ($r[$field] !== [] && array_is_list($r[$field])) {
                $renamed = [];
                foreach ($r[$field] as $i => $v) {
                    $renamed[$prefix . $i] = $v;
                }
                $r[$field] = $renamed;
            }
        }
        return $r;
    }

    /**
     * Pfad eines Anfragefehlers (requestError in validate.go). Für Zahlen- und Listenfelder nennt der Validator kein
     * einzelnes Feld; dort sucht der Server das Feld anhand derselben Grenzen.
     *
     * @param array<string, mixed> $r
     */
    private static function requestError(string $p, array $r, string $msg): IngestError
    {
        if (str_ends_with($msg, ': ' . self::TYPE_ERROR)) {
            return self::fieldError($p, $msg, []);
        }
        if (str_starts_with($msg, 'Token-Wert')) {
            foreach (['input', 'output', 'cache_create', 'cache_read', 'cache_1h', 'cache_5m', 'thinking'] as $f) {
                if ($r[$f] < 0 || $r[$f] > Limits::MAX_TOKENS_PER_FIELD) {
                    return new IngestError("$p.$f", 'außerhalb des Bereichs');
                }
            }
        } elseif (str_starts_with($msg, 'web_search/web_fetch')) {
            if ($r['web_search'] < 0 || $r['web_search'] > Limits::MAX_COUNT_PER_FIELD) {
                return new IngestError("$p.web_search", 'außerhalb des Bereichs');
            }
            return new IngestError("$p.web_fetch", 'außerhalb des Bereichs');
        } elseif (str_contains($msg, 'Werkzeug')) {
            return new IngestError("$p.tools", $msg);
        } elseif (str_contains($msg, 'extra')) {
            $at = strpos($msg, 'extra-');
            return new IngestError("$p.extra", $at === false ? $msg : substr_replace($msg, '', $at, strlen('extra-')));
        }
        return self::fieldError($p, $msg, ['message_id', 'request_id', 'session_id', 'account_id', 'model', 'ts', 'utc_offset_min', 'stop_reason']);
    }

    /**
     * Übersetzt eine Meldung des Validators in einen genauen Pfad (fieldError in validate.go): steht eines der
     * genannten Felder vorn, wird es Teil des Pfads und fällt aus der Meldung. Typfehler ("<feld>: falscher Typ …")
     * spaltet es immer ab; sie kommen nur vor, wenn der Dekodierer etwas durchließ.
     *
     * @param list<string> $fields
     */
    private static function fieldError(string $p, string $msg, array $fields): IngestError
    {
        $suffix = ': ' . self::TYPE_ERROR;
        if (str_ends_with($msg, $suffix)) {
            return new IngestError(self::join($p, substr($msg, 0, -strlen($suffix))), self::TYPE_ERROR);
        }
        foreach ($fields as $f) {
            if (!str_starts_with($msg, $f)) {
                continue;
            }
            $rest = substr($msg, strlen($f));
            if (str_starts_with($rest, ': ')) {
                return new IngestError(self::join($p, $f), substr($rest, 2));
            }
            if (str_starts_with($rest, ' ')) {
                return new IngestError(self::join($p, $f), substr($rest, 1));
            }
        }
        return new IngestError($p, $msg);
    }

    private static function join(string $p, string $f): string
    {
        return $p === '' ? $f : $p . '.' . $f;
    }

    /**
     * Ende (Byte-Position danach) des ersten JSON-Werts nach führendem Leerraum, ohne ihn zu prüfen; null, wenn
     * keiner da ist oder er nicht endet. So lässt sich Text nach dem Objekt von kaputtem JSON unterscheiden,
     * wie bei Gos json.Decoder, der genau einen Wert liest.
     */
    private static function firstValueEnd(string $s): ?int
    {
        $n = strlen($s);
        $i = strspn($s, self::WS);
        if ($i >= $n) {
            return null;
        }
        $c = $s[$i];
        if ($c === '"') {
            return self::stringEnd($s, $i);
        }
        if ($c !== '{' && $c !== '[') {
            // Zahl oder Literal: bis zum nächsten Leerraum oder Strukturzeichen.
            return $i + max(1, strcspn($s, self::WS . '{}[],:"', $i));
        }
        $depth = 0;
        while (true) {
            $i += strcspn($s, '{}[]"', $i);
            if ($i >= $n) {
                return null;
            }
            $c = $s[$i];
            if ($c === '"') {
                $i = self::stringEnd($s, $i);
                if ($i === null) {
                    return null;
                }
                continue;
            }
            if ($c === '{' || $c === '[') {
                $depth++;
            } elseif (--$depth === 0) {
                return $i + 1;
            }
            $i++;
        }
    }

    /** Position nach dem schließenden Anführungszeichen des Texts, der bei $i beginnt; null, wenn er nicht endet. */
    private static function stringEnd(string $s, int $i): ?int
    {
        $n = strlen($s);
        $i++;
        while (true) {
            $i += strcspn($s, '"\\', $i);
            if ($i >= $n) {
                return null;
            }
            if ($s[$i] === '"') {
                return $i + 1;
            }
            $i += 2;
        }
    }

    /**
     * Liest einen RFC-3339-Zeitstempel wie Gos time.Time (gleiches Muster wie Protocol\Validator) und liefert
     * Millisekunden seit 1970 in UTC (Bruchteile abgeschnitten); null, wenn er nicht passt.
     */
    private static function parseTimestamp(string $v): ?int
    {
        if (preg_match(
            '/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))\z/',
            $v,
            $m,
        ) !== 1) {
            return null;
        }
        [$y, $mo, $d, $h, $mi, $s] = [(int) $m[1], (int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], (int) $m[6]];
        $leap = $y % 4 === 0 && ($y % 100 !== 0 || $y % 400 === 0);
        $days = [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if ($mo < 1 || $mo > 12 || $d < 1 || $d > $days[$mo - 1] || $h > 23 || $mi > 59 || $s > 59) {
            return null;
        }
        $offset = 0;
        if (isset($m[8]) && $m[8] !== '') {
            $oh = (int) $m[9];
            $om = (int) $m[10];
            if ($oh > 23 || $om > 59) {
                return null;
            }
            $offset = ($m[8] === '-' ? -1 : 1) * ($oh * 3600 + $om * 60);
        }
        $ms = (int) substr(str_pad($m[7] ?? '', 3, '0'), 0, 3);
        return (self::daysFromCivil($y, $mo, $d) * 86400 + $h * 3600 + $mi * 60 + $s - $offset) * 1000 + $ms;
    }

    /** Tage seit 1970-01-01 im gregorianischen Kalender (Algorithmus von Howard Hinnant, wie im Validator). */
    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        if ($m <= 2) {
            $y--;
        }
        $era = intdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = intdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + intdiv($yoe, 4) - intdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }
}
