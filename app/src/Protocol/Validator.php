<?php

declare(strict_types=1);

namespace Tokenlore\Protocol;

// Prüft Plugin-Daten wie https://github.com/tokenlore/tokenlore/blob/main/protocol/validate.go: gleiche Regeln, Grenzen und Fehlertexte.
// Eingaben sind dekodierte JSON-Arrays (json_decode(..., true)). Rückgabe: null = gültig, sonst der Fehlertext.
//
// Go erzwingt Typen schon beim Dekodieren in seine Strukturen; PHP tut das nicht. Diese Prüfung steht deshalb
// vor den Wertregeln und meldet "<feld>: falscher Typ oder Zahl außerhalb des Bereichs", den Text des Go-Dekodierers
// (internal/ingest/decode.go) mit dem Feldnamen davor, damit der Aufrufer wie bei den übrigen Meldungen den Pfad
// abspalten kann. Ein fehlendes Feld oder null gilt wie in Go als Nullwert ("", 0, false). Zahlenfelder müssen
// Integer sein (1.0 lehnt Go ebenfalls ab); ein Integer außerhalb von int64 kommt in PHP als float an und fällt
// damit durch. Unbekannte Felder prüft der Dekodierer, nicht diese Klasse.
final class Validator
{
    public const TYPE_ERROR = 'falscher Typ oder Zahl außerhalb des Bereichs';

    /** @var list<string>|null */
    private static ?array $zones = null;

    /** @param array<mixed> $r Anfrage; $nowMs ist die Uhr des Prüfenden in Millisekunden seit 1970 (UTC). */
    public static function request(array $r, int $nowMs): ?string
    {
        $err = self::types($r, [
            'request_id' => 'string', 'message_id' => 'string', 'session_id' => 'string',
            'utc_offset_min' => 'int', 'model' => 'string',
            'input' => 'int', 'output' => 'int', 'cache_create' => 'int', 'cache_read' => 'int',
            'cache_1h' => 'int', 'cache_5m' => 'int', 'thinking' => 'int',
            'web_search' => 'int', 'web_fetch' => 'int',
            'stop_reason' => 'string', 'subagent' => 'bool', 'tools' => 'intmap',
            'account_id' => 'string', 'extra' => 'object',
        ]);
        if ($err !== null) {
            return $err;
        }
        $ts = self::parseTimestamp($r['ts'] ?? null);
        if ($ts === null) {
            return 'ts ungültig';
        }

        if (!self::matches(Limits::ID_PATTERN, $r['message_id'] ?? '')) {
            return 'message_id ungültig';
        }
        $requestId = $r['request_id'] ?? '';
        if ($requestId !== '' && !self::matches(Limits::ID_PATTERN, $requestId)) {
            return 'request_id ungültig';
        }
        if (!self::matches(Limits::ID_PATTERN, $r['session_id'] ?? '')) {
            return 'session_id ungültig';
        }
        $accountId = $r['account_id'] ?? '';
        if ($accountId !== '' && !self::matches(Limits::ID_PATTERN, $accountId)) {
            return 'account_id ungültig';
        }
        if (!self::matches(Limits::MODEL_PATTERN, $r['model'] ?? '')) {
            return 'model ungültig';
        }
        if ($ts[0] < Limits::EARLIEST_UNIX) {
            return 'ts vor 2024';
        }
        if (self::isAfter($ts, $nowMs + Limits::MAX_FUTURE_SKEW_MS)) {
            return 'ts liegt in der Zukunft';
        }
        $offset = $r['utc_offset_min'] ?? 0;
        if ($offset < -14 * 60 || $offset > 14 * 60) {
            return 'utc_offset_min außerhalb ±14 h';
        }
        foreach (['input', 'output', 'cache_create', 'cache_read', 'cache_1h', 'cache_5m', 'thinking'] as $f) {
            $v = $r[$f] ?? 0;
            if ($v < 0 || $v > Limits::MAX_TOKENS_PER_FIELD) {
                return 'Token-Wert außerhalb des Bereichs';
            }
        }
        $webSearch = $r['web_search'] ?? 0;
        $webFetch = $r['web_fetch'] ?? 0;
        if ($webSearch < 0 || $webSearch > Limits::MAX_COUNT_PER_FIELD || $webFetch < 0 || $webFetch > Limits::MAX_COUNT_PER_FIELD) {
            return 'web_search/web_fetch außerhalb des Bereichs';
        }
        $stop = $r['stop_reason'] ?? '';
        if ($stop !== '' && !self::matches(Limits::STOP_PATTERN, $stop)) {
            return 'stop_reason ungültig';
        }
        $tools = $r['tools'] ?? [];
        if (count($tools) > Limits::MAX_TOOLS) {
            return 'mehr als ' . Limits::MAX_TOOLS . ' Werkzeuge';
        }
        foreach ($tools as $name => $n) {
            $n ??= 0;
            // PHP macht aus Schlüsseln wie "123" ganze Zahlen; in Go sind es Texte.
            if (!self::matches(Limits::TOOL_PATTERN, (string) $name) || $n < 1 || $n > Limits::MAX_COUNT_PER_FIELD) {
                return 'Werkzeug ungültig';
            }
        }
        $extra = $r['extra'] ?? [];
        if (count($extra) > Limits::MAX_EXTRA_FIELDS) {
            return 'mehr als ' . Limits::MAX_EXTRA_FIELDS . ' extra-Felder';
        }
        foreach ($extra as $k => $v) {
            if (!self::matches(Limits::EXTRA_KEY, (string) $k)) {
                return 'extra-Schlüssel ungültig';
            }
            if (is_int($v) || is_float($v)) {
                if (is_float($v) && (is_nan($v) || is_infinite($v))) {
                    return 'extra-Zahl ungültig';
                }
            } elseif (is_string($v)) {
                if (mb_strlen($v, 'UTF-8') > Limits::MAX_EXTRA_STRING || self::hasControl($v) || self::hasSpoofChar($v)) {
                    return 'extra-Text ungültig';
                }
            } else {
                return 'extra-Wert ist weder Zahl noch Text';
            }
        }
        return null;
    }

    /** @param array<mixed> $s */
    public static function session(array $s): ?string
    {
        $err = self::types($s, ['session_id' => 'string', 'project_id' => 'string', 'cc_version' => 'string', 'account_id' => 'string']);
        if ($err !== null) {
            return $err;
        }
        if (!self::matches(Limits::ID_PATTERN, $s['session_id'] ?? '')) {
            return 'session_id ungültig';
        }
        $project = $s['project_id'] ?? '';
        if ($project !== '' && !self::matches(Limits::PROJECT_PATTERN, $project)) {
            return 'project_id ungültig';
        }
        $version = $s['cc_version'] ?? '';
        if ($version !== '' && !self::matches(Limits::VERSION_PATTERN, $version)) {
            return 'cc_version ungültig';
        }
        $accountId = $s['account_id'] ?? '';
        if ($accountId !== '' && !self::matches(Limits::ID_PATTERN, $accountId)) {
            return 'account_id ungültig';
        }
        return null;
    }

    /** Prüft ein Konto. Bei "off" darf keine Adresse mitkommen. @param array<mixed> $a */
    public static function account(array $a): ?string
    {
        $err = self::types($a, ['account_id' => 'string', 'email_mode' => 'string', 'email' => 'string']);
        if ($err !== null) {
            return $err;
        }
        if (!self::matches(Limits::ID_PATTERN, $a['account_id'] ?? '')) {
            return 'account_id ungültig';
        }
        $email = $a['email'] ?? '';
        switch ($a['email_mode'] ?? '') {
            case Limits::EMAIL_OFF:
                if ($email !== '') {
                    return 'Adresse trotz email_mode off';
                }
                break;
            case Limits::EMAIL_SHORT:
            case Limits::EMAIL_FULL:
                // Länge in Byte, wie len() in Go.
                if ($email !== '' && (strlen($email) > Limits::MAX_EMAIL_LEN || !str_contains($email, '@')
                    || self::hasControl($email) || self::hasSpoofChar($email) || strpbrk($email, ' <>"') !== false)) {
                    return 'Adresse ungültig';
                }
                break;
            default:
                return 'email_mode ungültig';
        }
        return null;
    }

    /** Prüft die Gerätedaten eines Pakets. @param array<mixed> $d */
    public static function device(array $d): ?string
    {
        $err = self::types($d, ['os' => 'string', 'arch' => 'string', 'tz' => 'string', 'plugin_version' => 'string'], 'device.');
        if ($err !== null) {
            return $err;
        }
        if (!in_array($d['os'] ?? '', ['windows', 'linux', 'darwin'], true)) {
            return 'device.os nicht erlaubt';
        }
        if (!in_array($d['arch'] ?? '', ['amd64', 'arm64'], true)) {
            return 'device.arch nicht erlaubt';
        }
        $tz = $d['tz'] ?? '';
        // "Local" würde die Zeitzone des Servers statt der des Geräts meinen.
        if ($tz === '' || strlen($tz) > Limits::MAX_TZ_LEN || $tz === 'Local') {
            return 'device.tz ungültig';
        }
        if (!self::knownZone($tz)) {
            return 'device.tz unbekannte Zeitzone';
        }
        if (!self::matches(Limits::VERSION_PATTERN, $d['plugin_version'] ?? '')) {
            return 'device.plugin_version ungültig';
        }
        return null;
    }

    /** Prüft einen Tageswert je Modell aus dem Altbestand. @param array<mixed> $d */
    public static function legacyModel(array $d, int $nowMs): ?string
    {
        $err = self::types($d, ['date' => 'string', 'model' => 'string', 'tokens' => 'int']);
        if ($err !== null) {
            return $err;
        }
        $err = self::checkLegacyDate($d['date'] ?? '', $nowMs);
        if ($err !== null) {
            return $err;
        }
        if (!self::matches(Limits::MODEL_PATTERN, $d['model'] ?? '')) {
            return 'model ungültig';
        }
        $tokens = $d['tokens'] ?? 0;
        if ($tokens < 0 || $tokens > Limits::MAX_LEGACY_NUMBER) {
            return 'tokens außerhalb des Bereichs';
        }
        return null;
    }

    /** Prüft einen Aktivitäts-Tageswert aus dem Altbestand. @param array<mixed> $d */
    public static function legacyActivity(array $d, int $nowMs): ?string
    {
        $err = self::types($d, ['date' => 'string', 'messages' => 'int', 'sessions' => 'int', 'tool_calls' => 'int']);
        if ($err !== null) {
            return $err;
        }
        $err = self::checkLegacyDate($d['date'] ?? '', $nowMs);
        if ($err !== null) {
            return $err;
        }
        foreach (['messages', 'sessions', 'tool_calls'] as $f) {
            $v = $d[$f] ?? 0;
            if ($v < 0 || $v > Limits::MAX_LEGACY_NUMBER) {
                return $f . ' außerhalb des Bereichs';
            }
        }
        return null;
    }

    /** Prüft einen vom Nutzer vergebenen Gerätenamen. */
    public static function deviceName(string $n): bool
    {
        if (!mb_check_encoding($n, 'UTF-8')) {
            return false;
        }
        $len = mb_strlen($n, 'UTF-8');
        if ($len < 1 || $len > Limits::MAX_DEVICE_NAME) {
            return false;
        }
        return !self::hasControl($n) && !self::hasSpoofChar($n);
    }

    /** Steuerzeichen (Unicode Cc), wie unicode.IsControl. */
    private static function hasControl(string $s): bool
    {
        return preg_match('/[\p{Cc}]/u', $s) === 1;
    }

    /**
     * Format-, Zeilen-, Absatztrenner- und Privatzeichen (z. B. U+202E, U+200B, U+2028), die in der Oberfläche
     * Text vortäuschen könnten. hasControl erfasst nur Steuerzeichen.
     */
    private static function hasSpoofChar(string $s): bool
    {
        return preg_match('/[\p{Cf}\p{Zl}\p{Zp}\p{Co}]/u', $s) === 1;
    }

    /** Muster passen nur auf Text; Nicht-Text kommt hier nach der Typprüfung nicht mehr an. */
    private static function matches(string $pattern, mixed $v): bool
    {
        return is_string($v) && preg_match($pattern, $v) === 1;
    }

    /**
     * Prüft die Feldtypen wie Gos Dekodierer. Fehlendes Feld und null zählen als Nullwert und bestehen.
     * "object" ist ein JSON-Objekt (leer oder mit Schlüsseln, keine Liste), "intmap" ein Objekt mit Integer-Werten.
     *
     * @param array<mixed> $d
     * @param array<string, string> $spec
     */
    private static function types(array $d, array $spec, string $prefix = ''): ?string
    {
        foreach ($spec as $field => $type) {
            $v = $d[$field] ?? null;
            if ($v === null) {
                continue;
            }
            $ok = match ($type) {
                'string' => is_string($v),
                'int' => is_int($v),
                'bool' => is_bool($v),
                'object' => self::isObject($v),
                'intmap' => self::isIntMap($v),
                default => false,
            };
            if (!$ok) {
                return $prefix . $field . ': ' . self::TYPE_ERROR;
            }
        }
        return null;
    }

    /** Objekt, dessen Werte alle Integer oder null sind (null zählt wie in Go als 0). */
    private static function isIntMap(mixed $v): bool
    {
        if (!self::isObject($v)) {
            return false;
        }
        foreach ($v as $n) {
            if ($n !== null && !is_int($n)) {
                return false;
            }
        }
        return true;
    }

    /** json_decode(..., true) macht aus {} und [] beide ein leeres Array; nicht leere Listen sind kein Objekt. */
    private static function isObject(mixed $v): bool
    {
        return is_array($v) && ($v === [] || !array_is_list($v));
    }

    /**
     * Liest einen RFC-3339-Zeitstempel (wie Gos time.Time) als [Unix-Sekunden, Nanosekunden].
     * Fehlend oder null ist wie in Go die Nullzeit (Jahr 1). Alles andere, was nicht parst, gibt null zurück.
     *
     * @return array{int, int}|null
     */
    private static function parseTimestamp(mixed $v): ?array
    {
        if ($v === null) {
            return [self::daysFromCivil(1, 1, 1) * 86400, 0];
        }
        if (!is_string($v) || preg_match(
            '/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))\z/',
            $v,
            $m,
        ) !== 1) {
            return null;
        }
        [$y, $mo, $d, $h, $mi, $s] = [(int) $m[1], (int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], (int) $m[6]];
        if (!self::validDate($y, $mo, $d) || $h > 23 || $mi > 59 || $s > 59) {
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
        $nanos = (int) substr(str_pad($m[7] ?? '', 9, '0'), 0, 9);
        return [self::daysFromCivil($y, $mo, $d) * 86400 + $h * 3600 + $mi * 60 + $s - $offset, $nanos];
    }

    /** True, wenn der Zeitpunkt $ts (Sekunden, Nanosekunden) nach $limitMs (Millisekunden) liegt. @param array{int, int} $ts */
    private static function isAfter(array $ts, int $limitMs): bool
    {
        $sec = intdiv($limitMs, 1000);
        $ms = $limitMs % 1000;
        if ($ms < 0) {
            $ms += 1000;
            $sec--;
        }
        return $ts[0] > $sec || ($ts[0] === $sec && $ts[1] > $ms * 1_000_000);
    }

    /** Tage von 2024-01-01 bis einschließlich morgen (UTC); morgen wegen Zeitzonen. */
    private static function checkLegacyDate(mixed $s, int $nowMs): ?string
    {
        if (!self::matches(Limits::LEGACY_DATE_PATTERN, $s)) {
            return 'date: Format YYYY-MM-DD erwartet';
        }
        if (!self::validDate((int) substr($s, 0, 4), (int) substr($s, 5, 2), (int) substr($s, 8, 2))) {
            return 'date: kein gültiges Datum';
        }
        $sec = intdiv($nowMs, 1000);
        if ($nowMs % 1000 < 0) {
            $sec--;
        }
        $latest = gmdate('Y-m-d', $sec + 86400);
        // Beide Seiten sind YYYY-MM-DD; die Textordnung ist die Zeitordnung.
        if ($s < Limits::EARLIEST_DATE || $s > $latest) {
            return 'date: außerhalb des erlaubten Zeitraums';
        }
        return null;
    }

    private static function validDate(int $y, int $m, int $d): bool
    {
        if ($m < 1 || $m > 12 || $d < 1) {
            return false;
        }
        $leap = $y % 4 === 0 && ($y % 100 !== 0 || $y % 400 === 0);
        $days = [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        return $d <= $days[$m - 1];
    }

    /** Tage seit 1970-01-01 im gregorianischen Kalender (Algorithmus von Howard Hinnant); gmmktime kennt kein Jahr 1. */
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

    /**
     * Go lädt Zeitzonen aus seiner eingebauten Datenbank, mit Groß-/Kleinschreibung und samt Altnamen
     * (US/Eastern, EST5EDT, Zulu). new DateTimeZone() nähme dagegen auch "europe/berlin", "CEST" und "+02:00".
     * Deshalb zählt nur, was die Liste von PHP einschließlich Altnamen genau so enthält.
     * Die Liste stammt aus der Zeitzonendatenbank der laufenden PHP-Version und kann von der in Go
     * eingebauten Liste leicht abweichen (neue oder umbenannte Zonen).
     */
    private static function knownZone(string $tz): bool
    {
        self::$zones ??= \DateTimeZone::listIdentifiers(\DateTimeZone::ALL_WITH_BC);
        return in_array($tz, self::$zones, true);
    }
}
