<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

use stdClass;
use Tokenlore\Protocol\Limits;
use Tokenlore\Protocol\Signature;
use Tokenlore\Protocol\Validator;

// Liest und prüft Lieferpakete (Protokoll Version 2, protocol/doc.md im Plugin-Repo) in der Reihenfolge der
// „Prüfregeln des Servers“: Mindestversion (426), Paketform und Grenzen, Signatur je Zeile, Inhaltszeile (je 400 mit
// Pfad). Fehler nennen nur den Feldpfad und was daran falsch ist, nie den Wert.
//
// JSON wird mit Objekten statt assoziativen Arrays dekodiert. Nur so bleiben {} und [] unterscheidbar, und ein
// Objekt mit den Schlüsseln "0", "1" (z. B. Werkzeuge namens "0") wird nicht für eine Liste gehalten. Feldnamen des
// Pakets passen wie bei Gos encoding/json auch ohne Beachtung der Groß-/Kleinschreibung; die Hüllen und die signierten
// Inhaltszeilen dagegen nur mit genau den Schlüsseln aus dem Protokoll.
final class Decoder
{
    /** Protokollversion, die jede Lieferung trägt. */
    public const VERSION = Limits::PROTOCOL_VERSION;

    public const TYPE_ERROR = Validator::TYPE_ERROR;

    // Kontenliste: Grenze vor dem Dekodieren der Elemente.
    private const MAX_ACCOUNTS = 1000;

    // Höchste Schachtelungstiefe; Gos Dekodierer bricht ab 10.000 Ebenen mit einem Syntaxfehler ab.
    private const MAX_DEPTH = 10_000;

    private const WS = " \t\n\r";

    // Felder der Strukturen mit ihrem Typ.
    private const DEVICE = ['os' => 'string', 'arch' => 'string', 'tz' => 'string', 'plugin_version' => 'string'];
    private const ACCOUNT = ['account_id' => 'string', 'email_mode' => 'string', 'email' => 'string'];
    private const SESSION = ['session_id' => 'string', 'cc_version' => 'string', 'account_id' => 'string'];

    // Listen in der Reihenfolge, in der ihre Elemente dekodiert werden; null steht für Hüllen (z, s).
    private const LISTS = [
        'accounts' => self::ACCOUNT,
        'sessions' => self::SESSION,
        'requests' => null,
        'legacy_days' => null,
    ];

    // Listengrenzen in der Reihenfolge, in der sie vor den Elementen geprüft werden.
    private const LIST_LIMITS = [
        'requests' => Limits::MAX_REQUESTS_PER_BATCH,
        'legacy_days' => Limits::MAX_LEGACY_LIST,
        'accounts' => self::MAX_ACCOUNTS,
        'sessions' => Limits::MAX_SESSIONS_PER_BATCH,
    ];

    /**
     * Liest genau ein Paket-Objekt. Zuerst die Mindestversion: ist device.plugin_version älter als
     * Limits::MIN_PLUGIN_VERSION (oder fehlt sie), folgt PluginOutdated vor jeder weiteren Prüfung, damit auch ein
     * altes Plugin mit anderer Paketform die Meldung „aktualisieren“ bekommt. Danach sind unbekannte Felder, falsche
     * Typen und Text nach dem Objekt Fehler; null gilt als Nullwert.
     * Ergebnis: v, device (os, arch, tz, plugin_version) und die Listen accounts und sessions (jedes Element mit allen
     * Feldern, "" wenn nicht da) sowie requests und legacy_days als Hüllen ['z' => Text, 's' => Text oder null].
     * Die Rumpfgrenze setzt der Aufrufer.
     *
     * @return array<string, mixed>
     * @throws IngestError
     * @throws PluginOutdated
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
        $version = self::pluginVersion($top);
        if ($version !== null && Validator::pluginOutdated($version)) {
            throw new PluginOutdated();
        }

        // Erste Stufe: Listen bleiben unzerlegt, damit ihre Länge vor den Elementen geprüft wird. Der Durchlauf merkt
        // sich den ersten Fehler in Dokumentreihenfolge; ein Listenfehler bricht sofort ab.
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
            } elseif (array_key_exists($name, self::LISTS)) {
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
                if ($spec === null) {
                    $out[] = self::envelope($el, $path);
                    continue;
                }
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
     * Prüft ein dekodiertes Paket und liest die signierten Zeilen. Reihenfolge laut „Prüfregeln des Servers“: erst
     * Paketform und Grenzen (Version, Gerät, Konten, Sitzungen, Hüllen), dann die Signatur jeder Zeile gegen $signKeys,
     * dann jede Inhaltszeile. Der erste Fehler bricht ab.
     *
     * Ergebnis: das Paket, in dem requests die gelesenen Anfragen und Fehlerzeilen (Validator::requestLine und
     * errorLine, unterschieden an kind) und legacy_days die gelesenen Tage (Validator::dayLine) sind, je mit z und s
     * wie geliefert.
     *
     * @param array<string, mixed> $b Ergebnis von decode()
     * @param int $nowMs Uhr des Servers in Millisekunden
     * @param list<string> $signKeys Signaturschlüssel des liefernden Geräts (Devices::signKeys), 32 Byte roh
     * @return array<string, mixed>
     * @throws IngestError
     */
    public static function validate(array $b, int $nowMs, array $signKeys): array
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
        foreach ($b['sessions'] as $i => $s) {
            $err = Validator::session($s);
            if ($err !== null) {
                throw self::fieldError("sessions[$i]", $err, ['session_id', 'cc_version', 'account_id']);
            }
        }
        foreach (['requests', 'legacy_days'] as $list) {
            foreach ($b[$list] as $i => $e) {
                if (strlen($e['z']) > Limits::MAX_LINE_BYTES) {
                    throw new IngestError("{$list}[$i].z", 'länger als ' . Limits::MAX_LINE_BYTES . ' Byte');
                }
                if (!mb_check_encoding($e['z'], 'UTF-8')) {
                    throw new IngestError("{$list}[$i].z", 'kein gültiges UTF-8');
                }
            }
        }

        // Signatur: der zuletzt passende Schlüssel wird zuerst versucht (meist passt für alle Zeilen derselbe).
        $order = $signKeys;
        foreach (['requests', 'legacy_days'] as $list) {
            foreach ($b[$list] as $i => $e) {
                $path = "{$list}[$i].s";
                if ($e['s'] === null) {
                    throw new IngestError($path, 'Signatur fehlt');
                }
                $sig = Signature::decode($e['s']);
                if ($sig === null) {
                    throw new IngestError($path, 'Signatur ungültig');
                }
                $hit = Signature::matchingKey($e['z'], $sig, $order);
                if ($hit === null) {
                    throw new IngestError($path, 'Signatur passt zu keinem Schlüssel des Geräts', 400, IngestError::REASON_SIGN_KEY_UNKNOWN);
                }
                if ($hit !== 0) {
                    $key = $order[$hit];
                    unset($order[$hit]);
                    array_unshift($order, $key);
                }
            }
        }

        foreach (['requests' => 'requestLine', 'legacy_days' => 'dayLine'] as $list => $check) {
            $rows = [];
            foreach ($b[$list] as $i => $e) {
                $path = "{$list}[$i].z";
                try {
                    $line = json_decode($e['z'], false, 64, JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    throw new IngestError($path, 'kein gültiges JSON');
                }
                $err = self::lineForm($e['z']);
                if ($err !== null) {
                    throw new IngestError(self::join($path, $err[0]), $err[1]);
                }
                // In requests stehen Anfragen und Fehlerzeilen; unterschieden wird nach kind.
                $lineCheck = $list === 'requests' && $line instanceof stdClass && ($line->kind ?? null) === 'error' ? 'errorLine' : $check;
                $err = Validator::$lineCheck($line, $nowMs, $out);
                if ($err !== null) {
                    throw new IngestError(self::join($path, $err[0]), $err[1]);
                }
                $rows[] = $out + ['z' => $e['z'], 's' => $e['s']];
            }
            $b[$list] = $rows;
        }
        return $b;
    }

    /**
     * device.plugin_version, gelesen ohne die übrigen Prüfungen (Name ohne Beachtung der Groß-/Kleinschreibung wie
     * beim Dekodieren): "" wenn Gerät oder Version fehlen oder null sind, null wenn ein Wert den falschen Typ hat
     * (das meldet danach die Formprüfung).
     */
    private static function pluginVersion(stdClass $top): ?string
    {
        $version = '';
        foreach (get_object_vars($top) as $key => $device) {
            if (strtolower((string) $key) !== 'device') {
                continue;
            }
            $version = '';
            if ($device === null) {
                continue;
            }
            if (!$device instanceof stdClass) {
                return null;
            }
            foreach (get_object_vars($device) as $field => $v) {
                if (strtolower((string) $field) !== 'plugin_version' || $v === null) {
                    continue;
                }
                if (!is_string($v)) {
                    return null;
                }
                $version = $v;
            }
        }
        return $version;
    }

    /**
     * Liest eine Hülle: ein Objekt mit genau den Schlüsseln z (Text, Pflicht) und s (Text; fehlt s, meldet das die
     * Signaturprüfung mit ihrem Pfad).
     *
     * @return array{z: string, s: string|null}
     */
    private static function envelope(mixed $el, string $path): array
    {
        if (!$el instanceof stdClass) {
            throw new IngestError($path, self::TYPE_ERROR);
        }
        $v = get_object_vars($el);
        foreach ($v as $k => $_) {
            if ($k !== 'z' && $k !== 's') {
                throw new IngestError($path, 'unbekanntes Feld');
            }
        }
        if (!isset($v['z'])) {
            throw new IngestError("$path.z", 'fehlt');
        }
        if (!is_string($v['z'])) {
            throw new IngestError("$path.z", self::TYPE_ERROR);
        }
        $s = $v['s'] ?? null;
        if ($s !== null && !is_string($s)) {
            throw new IngestError("$path.s", self::TYPE_ERROR);
        }
        return ['z' => $v['z'], 's' => $s];
    }

    /**
     * Dekodiert ein Objekt in die Textfelder von $spec (wie encoding/json in eine Struktur). Unbekannte Felder und
     * Typfehler merkt sich $saved (nur der erste zählt); null lässt den Wert unverändert.
     *
     * @param array<string, string> $spec Feld => 'string'
     * @param array<string, mixed> $into Nullwerte bzw. bisheriger Stand
     * @return array<string, mixed>
     */
    private static function struct(stdClass $o, array $spec, string $typePrefix, string $path, ?IngestError &$saved, array $into): array
    {
        foreach (get_object_vars($o) as $key => $v) {
            $field = strtolower((string) $key);
            if (!isset($spec[$field])) {
                $saved ??= new IngestError($path, 'unbekanntes Feld');
                continue;
            }
            if ($v === null) {
                continue;
            }
            if (!is_string($v)) {
                $saved ??= new IngestError($typePrefix . '.' . $field, self::TYPE_ERROR);
                continue;
            }
            $into[$field] = $v;
        }
        return $into;
    }

    /** @param array<string, string> $spec @return array<string, string> */
    private static function zero(array $spec): array
    {
        return array_fill_keys(array_keys($spec), '');
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
        return $p === '' || $f === '' ? $p . $f : $p . '.' . $f;
    }

    /**
     * Form einer Inhaltszeile, die json_decode nicht sieht: kompakt (kein Leerraum außerhalb von Texten, so schreibt das
     * Plugin z mit MarshalLine) und kein Schlüssel doppelt in einem Objekt, auf jeder Ebene. json_decode nähme bei
     * doppelten Schlüsseln still den letzten Wert; ein anderer Leser von z sähe dann andere Werte als die Spalten.
     * Erwartet gültiges JSON (nach json_decode). Ergebnis: null oder [Pfad in z, Meldung]; der Pfad nennt das Objekt,
     * einen Schlüssel nur, wenn er Limits::EXTRA_KEY erfüllt (sonst endet er beim Objekt davor), nie den doppelten.
     *
     * @return array{0:string, 1:string}|null
     */
    private static function lineForm(string $z): ?array
    {
        $n = strlen($z);
        for ($i = 0; $i < $n;) {
            $j = $i + strcspn($z, '"' . self::WS, $i);
            if ($j >= $n) {
                break;
            }
            if ($z[$j] !== '"') {
                return ['', 'nicht kompakt (Leerraum außerhalb von Texten)'];
            }
            $i = self::stringEnd($z, $j) ?? $n;
        }
        $i = 0;
        return self::uniqueKeys($z, $i, '');
    }

    /**
     * Prüft den Wert ab Position $i (kompaktes, gültiges JSON) auf doppelte Schlüssel und setzt $i hinter ihn.
     *
     * @return array{0:string, 1:string}|null
     */
    private static function uniqueKeys(string $z, int &$i, string $path): ?array
    {
        $c = $z[$i];
        if ($c === '"') {
            $i = (int) self::stringEnd($z, $i);
            return null;
        }
        if ($c !== '{' && $c !== '[') {
            $i += strcspn($z, ',]}', $i);
            return null;
        }
        $i++;
        $close = $c === '{' ? '}' : ']';
        if ($z[$i] === $close) {
            $i++;
            return null;
        }
        $seen = [];
        for ($n = 0;; $n++) {
            $sub = $path . '[' . $n . ']';
            if ($c === '{') {
                $end = (int) self::stringEnd($z, $i);
                $key = (string) json_decode(substr($z, $i, $end - $i));
                if (isset($seen[$key])) {
                    return [$path, 'doppelter Schlüssel'];
                }
                $seen[$key] = true;
                $i = $end + 1; // hinter dem Doppelpunkt
                $sub = preg_match(Limits::EXTRA_KEY, $key) === 1 ? self::join($path, $key) : $path;
            }
            $err = self::uniqueKeys($z, $i, $sub);
            if ($err !== null) {
                return $err;
            }
            if ($z[$i++] === $close) {
                return null;
            }
        }
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
}
