<?php

declare(strict_types=1);

namespace Tokenlore\Protocol;

// Prüft Plugin-Daten wie https://github.com/tokenlore/tokenlore/blob/main/protocol/validate.go: gleiche Regeln, Grenzen und Fehlertexte.
// Eingaben sind dekodierte JSON-Arrays (json_decode(..., true)). Rückgabe: null = gültig, sonst der Fehlertext.
// Ausnahme: die signierten Inhaltszeilen (requestLine, dayLine) kommen als stdClass und liefern [Pfad, Meldung].
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

    // Inhaltszeilen (Abschnitt „Inhaltszeile“ in protocol/doc.md). Sie stammen aus dem Archiv des Plugins und sind
    // signiert; der Server liest sie aus genau dem gelieferten Text z (json_decode zu stdClass, damit {} und [] sich
    // unterscheiden). Die Prüfungen geben null oder [Pfad unter z, Meldung] zurück; Pfade enthalten nur feste
    // Feldnamen, nie Schlüssel oder Werte aus der Zeile.

    /** Felder einer Anfrage: Typ und ob Pflicht. */
    private const REQUEST_LINE = [
        'kind' => ['string', true], 'request_id' => ['string', true], 'message_id' => ['string', true],
        'session_id' => ['string', true], 'uuid' => ['string', false], 'parent_uuid' => ['string', false],
        'ts' => ['string', true], 'utc_offset_min' => ['int', true], 'model' => ['string', true],
        'requested_model' => ['string', false], 'effort' => ['string', false], 'entrypoint' => ['string', false],
        'cc_version' => ['string', false], 'stop_reason' => ['string', false], 'subagent' => ['bool', true],
        'tools' => ['object', false], 'account_id' => ['string', false], 'usage' => ['object', true],
    ];

    /** Felder eines Vorgeschichte-Tags. */
    private const DAY_LINE = [
        'kind' => ['string', true], 'date' => ['string', true], 'models' => ['object', false],
        'activity' => ['object', false], 'complete_before' => ['string', false],
    ];

    /**
     * Zählwerte einer Anfrage und ihr Pfad in usage (Tabelle „Zählwerte“); fehlt ein Wert, gilt 0.
     * Die Grenze ist MAX_TOKENS_PER_FIELD, für web_search und web_fetch MAX_COUNT_PER_FIELD.
     */
    public const USAGE_COUNTS = [
        'input' => ['input_tokens'],
        'output' => ['output_tokens'],
        'cache_create' => ['cache_creation_input_tokens'],
        'cache_read' => ['cache_read_input_tokens'],
        'cache_1h' => ['cache_creation', 'ephemeral_1h_input_tokens'],
        'cache_5m' => ['cache_creation', 'ephemeral_5m_input_tokens'],
        'thinking' => ['output_tokens_details', 'thinking_tokens'],
        'web_search' => ['server_tool_use', 'web_search_requests'],
        'web_fetch' => ['server_tool_use', 'web_fetch_requests'],
    ];

    /**
     * Prüft die Inhaltszeile einer Anfrage und liest ihre Werte.
     *
     * $out bei Erfolg: message_id, request_id, session_id, ts (Text), ts_ms (Millisekunden seit 1970, UTC),
     * utc_offset_min, model, die Zählwerte aus USAGE_COUNTS, stop_reason und account_id ('' wenn nicht da), subagent,
     * tools (Name => Anzahl) und extra (übrige Schlüssel der obersten Ebene von usage mit Zahl oder Text, alphabetisch,
     * höchstens MAX_EXTRA_FIELDS).
     *
     * @param mixed $o dekodierte Zeile; $nowMs ist die Uhr des Servers in Millisekunden
     * @param array<string, mixed>|null $out
     * @return array{0: string, 1: string}|null
     */
    public static function requestLine(mixed $o, int $nowMs, ?array &$out = null): ?array
    {
        $out = null;
        $err = self::lineShape($o, 'request', self::REQUEST_LINE);
        if ($err !== null) {
            return $err;
        }
        $v = get_object_vars($o);
        foreach (['message_id', 'session_id'] as $f) {
            if (!self::matches(Limits::ID_PATTERN, $v[$f])) {
                return [$f, 'ungültig'];
            }
        }
        if ($v['request_id'] !== '' && !self::matches(Limits::ID_PATTERN, $v['request_id'])) {
            return ['request_id', 'ungültig'];
        }
        foreach (['uuid', 'parent_uuid', 'account_id'] as $f) {
            if (isset($v[$f]) && !self::matches(Limits::ID_PATTERN, $v[$f])) {
                return [$f, 'ungültig'];
            }
        }
        $ts = self::matches(Limits::TS_PATTERN, $v['ts']) ? self::parseTimestamp($v['ts']) : null;
        if ($ts === null) {
            return ['ts', 'ungültig'];
        }
        if ($ts[0] < Limits::EARLIEST_UNIX) {
            return ['ts', 'vor 2024'];
        }
        if (self::isAfter($ts, $nowMs + Limits::MAX_FUTURE_SKEW_MS)) {
            return ['ts', 'liegt in der Zukunft'];
        }
        if ($v['utc_offset_min'] < -Limits::MAX_UTC_OFFSET_MIN || $v['utc_offset_min'] > Limits::MAX_UTC_OFFSET_MIN) {
            return ['utc_offset_min', 'außerhalb ±14 h'];
        }
        foreach (['model', 'requested_model'] as $f) {
            if (($f === 'model' || isset($v[$f])) && !self::matches(Limits::MODEL_PATTERN, $v[$f])) {
                return [$f, 'ungültig'];
            }
        }
        foreach (['effort', 'entrypoint', 'stop_reason'] as $f) {
            if (isset($v[$f]) && !self::matches(Limits::STOP_PATTERN, $v[$f])) {
                return [$f, 'ungültig'];
            }
        }
        if (isset($v['cc_version']) && !self::matches(Limits::VERSION_PATTERN, $v['cc_version'])) {
            return ['cc_version', 'ungültig'];
        }
        $tools = [];
        if (isset($v['tools'])) {
            $tools = get_object_vars($v['tools']);
            if (count($tools) > Limits::MAX_TOOLS) {
                return ['tools', 'mehr als ' . Limits::MAX_TOOLS . ' Werkzeuge'];
            }
            foreach ($tools as $name => $n) {
                // PHP macht aus Schlüsseln wie "123" ganze Zahlen; im JSON sind es Texte.
                if (!self::matches(Limits::TOOL_PATTERN, (string) $name) || !is_int($n) || $n < 1 || $n > Limits::MAX_COUNT_PER_FIELD) {
                    return ['tools', 'Werkzeug ungültig'];
                }
            }
        }
        $count = 0;
        $err = self::usageError($v['usage'], 1, $count);
        if ($err !== null) {
            return ['usage', $err];
        }
        $usage = $v['usage'];
        $numbers = [];
        foreach (self::USAGE_COUNTS as $name => $path) {
            [$present, $x] = self::pathValue($usage, $path);
            $max = in_array($name, ['web_search', 'web_fetch'], true) ? Limits::MAX_COUNT_PER_FIELD : Limits::MAX_TOKENS_PER_FIELD;
            if ($present && (!is_int($x) || $x < 0 || $x > $max)) {
                return ['usage.' . implode('.', $path), 'keine ganze Zahl im erlaubten Bereich'];
            }
            $numbers[$name] = $present ? $x : 0;
        }
        $extra = [];
        $counted = array_map(static fn(array $p): string => $p[0], array_filter(self::USAGE_COUNTS, static fn(array $p): bool => count($p) === 1));
        foreach (get_object_vars($usage) as $k => $x) {
            $k = (string) $k;
            if (!in_array($k, $counted, true) && (is_int($x) || is_float($x) || is_string($x))) {
                $extra[$k] = $x;
            }
        }
        ksort($extra, SORT_STRING);
        $extra = array_slice($extra, 0, Limits::MAX_EXTRA_FIELDS, true);

        $out = [
            'message_id' => $v['message_id'], 'request_id' => $v['request_id'], 'session_id' => $v['session_id'],
            'ts' => $v['ts'], 'ts_ms' => $ts[0] * 1000 + intdiv($ts[1], 1_000_000), 'utc_offset_min' => $v['utc_offset_min'],
            'model' => $v['model'],
        ] + $numbers + [
            'stop_reason' => $v['stop_reason'] ?? '', 'subagent' => $v['subagent'], 'tools' => $tools,
            'account_id' => $v['account_id'] ?? '', 'extra' => $extra,
        ];
        return null;
    }

    /**
     * Prüft die Inhaltszeile eines Vorgeschichte-Tags und liest ihre Werte.
     *
     * $out bei Erfolg: date, models (Modell => Tokens, leer wenn nicht da), activity (messages, sessions, tool_calls
     * oder null) und complete_before (Text oder null).
     *
     * @param mixed $o dekodierte Zeile
     * @param array<string, mixed>|null $out
     * @return array{0: string, 1: string}|null
     */
    public static function dayLine(mixed $o, int $nowMs, ?array &$out = null): ?array
    {
        $out = null;
        $err = self::lineShape($o, 'day', self::DAY_LINE);
        if ($err !== null) {
            return $err;
        }
        $v = get_object_vars($o);
        $err = self::checkLegacyDate($v['date'], $nowMs);
        if ($err !== null) {
            return ['date', substr($err, strlen('date: '))];
        }
        if (!isset($v['models']) && !isset($v['activity'])) {
            return ['', 'models oder activity fehlt'];
        }
        $models = [];
        if (isset($v['models'])) {
            $models = get_object_vars($v['models']);
            if (count($models) > Limits::MAX_LEGACY_MODELS) {
                return ['models', 'mehr als ' . Limits::MAX_LEGACY_MODELS . ' Modelle'];
            }
            foreach ($models as $name => $tokens) {
                if (!self::matches(Limits::MODEL_PATTERN, (string) $name) || !is_int($tokens) || $tokens < 0 || $tokens > Limits::MAX_LEGACY_NUMBER) {
                    return ['models', 'Modell ungültig'];
                }
            }
        }
        $activity = null;
        if (isset($v['activity'])) {
            $a = get_object_vars($v['activity']);
            $fields = ['messages', 'sessions', 'tool_calls'];
            if (array_diff(array_map('strval', array_keys($a)), $fields) !== []) {
                return ['activity', 'unbekanntes Feld'];
            }
            foreach ($fields as $f) {
                if (!array_key_exists($f, $a)) {
                    return ["activity.$f", 'fehlt'];
                }
                if (!is_int($a[$f]) || $a[$f] < 0 || $a[$f] > Limits::MAX_LEGACY_NUMBER) {
                    return ["activity.$f", 'außerhalb des Bereichs'];
                }
                $activity[$f] = $a[$f];
            }
        }
        if (isset($v['complete_before'])) {
            $err = self::legacyCompleteBefore($v['complete_before']);
            if ($err !== null) {
                return ['complete_before', $err];
            }
        }
        $out = ['date' => $v['date'], 'models' => $models, 'activity' => $activity, 'complete_before' => $v['complete_before'] ?? null];
        return null;
    }

    /**
     * Form einer Inhaltszeile: ein Objekt, kind wie erwartet, nur Schlüssel aus $spec, Pflichtfelder da, jeder Wert vom
     * richtigen Typ (null ist nie erlaubt: optionale Felder fehlen ganz).
     *
     * @param array<string, array{0: string, 1: bool}> $spec
     * @return array{0: string, 1: string}|null
     */
    private static function lineShape(mixed $o, string $kind, array $spec): ?array
    {
        if (!$o instanceof \stdClass) {
            return ['', 'kein JSON-Objekt'];
        }
        $v = get_object_vars($o);
        if (!array_key_exists('kind', $v) || $v['kind'] !== $kind) {
            return ['kind', 'nicht ' . $kind];
        }
        foreach ($v as $k => $_) {
            if (!isset($spec[(string) $k])) {
                // Den Namen aus der Zeile nie wiederholen.
                return ['', 'unbekanntes Feld'];
            }
        }
        foreach ($spec as $f => [$type, $required]) {
            if (!array_key_exists($f, $v)) {
                if ($required) {
                    return [$f, 'fehlt'];
                }
                continue;
            }
            $x = $v[$f];
            $ok = match ($type) {
                'string' => is_string($x),
                'int' => is_int($x),
                'bool' => is_bool($x),
                'object' => $x instanceof \stdClass,
            };
            if (!$ok) {
                return [$f, self::TYPE_ERROR];
            }
        }
        return null;
    }

    /**
     * Wert unter $path in $usage: [true, Wert], wenn jeder Schritt ein Objekt mit diesem Schlüssel ist (auch mit Wert
     * null), sonst [false, null].
     *
     * @param list<string> $path
     * @return array{0: bool, 1: mixed}
     */
    private static function pathValue(\stdClass $usage, array $path): array
    {
        $node = $usage;
        foreach ($path as $key) {
            if (!$node instanceof \stdClass || !property_exists($node, $key)) {
                return [false, null];
            }
            $node = $node->{$key};
        }
        return [true, $node];
    }

    /**
     * Grenzen von usage (Tabelle „Grenzen“): Objekte und Listen höchstens USAGE_MAX_DEPTH Ebenen tief (usage ist
     * Ebene 1), höchstens USAGE_MAX_VALUES Werte unterhalb von usage, Schlüssel nach EXTRA_KEY, Listen höchstens
     * USAGE_MAX_LIST Einträge; Werte endliche Zahl, true, false, null, Text bis MAX_EXTRA_STRING Zeichen ohne Steuer-
     * und Formatzeichen, Objekt oder Liste.
     */
    private static function usageError(\stdClass|array $node, int $depth, int &$count): ?string
    {
        if (is_array($node) && count($node) > Limits::USAGE_MAX_LIST) {
            return 'Liste mit mehr als ' . Limits::USAGE_MAX_LIST . ' Einträgen';
        }
        foreach (is_array($node) ? $node : get_object_vars($node) as $k => $x) {
            if ($node instanceof \stdClass && !self::matches(Limits::EXTRA_KEY, (string) $k)) {
                return 'Schlüssel ungültig';
            }
            if (++$count > Limits::USAGE_MAX_VALUES) {
                return 'mehr als ' . Limits::USAGE_MAX_VALUES . ' Werte';
            }
            if ($x instanceof \stdClass || is_array($x)) {
                if ($depth + 1 > Limits::USAGE_MAX_DEPTH) {
                    return 'mehr als ' . Limits::USAGE_MAX_DEPTH . ' Ebenen';
                }
                $err = self::usageError($x, $depth + 1, $count);
                if ($err !== null) {
                    return $err;
                }
            } elseif (is_float($x)) {
                if (!is_finite($x)) {
                    return 'Zahl ungültig';
                }
            } elseif (is_string($x)) {
                if (mb_strlen($x, 'UTF-8') > Limits::MAX_EXTRA_STRING || self::hasControl($x) || self::hasSpoofChar($x)) {
                    return 'Text ungültig';
                }
            }
        }
        return null;
    }

    /** @param array<mixed> $s */
    public static function session(array $s): ?string
    {
        $err = self::types($s, ['session_id' => 'string', 'cc_version' => 'string', 'account_id' => 'string']);
        if ($err !== null) {
            return $err;
        }
        if (!self::matches(Limits::ID_PATTERN, $s['session_id'] ?? '')) {
            return 'session_id ungültig';
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

    /**
     * Prüft einen öffentlichen Signaturschlüssel (sign_public_key, Einträge von sign_public_keys_previous): Base64 im
     * Standardalphabet mit Auffüllung, genau 44 Zeichen, 32 Byte. Nur die kanonische Form gilt (kodiert wieder genau
     * zum gesendeten Text), damit ein Schlüssel nur eine Schreibweise hat.
     *
     * @return string|null die 32 Byte roh; null, wenn ungültig
     */
    public static function signKey(string $s): ?string
    {
        $raw = base64_decode($s, true);
        if ($raw === false || strlen($raw) !== Limits::SIGN_KEY_BYTES || base64_encode($raw) !== $s) {
            return null;
        }
        return $raw;
    }

    /**
     * true, wenn die Plugin-Version älter als $min ist (Abschnitt „Mindestversion“ in protocol/doc.md): verglichen
     * werden die drei Zahlen x.y.z am Anfang, Zahl für Zahl; ein Zusatz danach zählt nicht. Eine Version, die nicht
     * mit x.y.z beginnt, gilt als zu alt. Die Zahlen werden als Ziffernfolgen verglichen, damit lange Zahlen nicht
     * überlaufen.
     */
    public static function pluginOutdated(string $version, string $min = Limits::MIN_PLUGIN_VERSION): bool
    {
        $parts = static function (string $v): ?array {
            if (preg_match('/^([0-9]+)\.([0-9]+)\.([0-9]+)/', $v, $m) !== 1) {
                return null;
            }
            return array_map(static fn(string $n): string => ltrim($n, '0'), array_slice($m, 1));
        };
        $have = $parts($version);
        $want = $parts($min);
        if ($have === null || $want === null) {
            return true;
        }
        foreach ($have as $i => $n) {
            $cmp = strlen($n) <=> strlen($want[$i]) ?: strcmp($n, $want[$i]) <=> 0;
            if ($cmp !== 0) {
                return $cmp < 0;
            }
        }
        return false;
    }

    /** Prüft die Kennung des Rechners beim Koppeln (device_source): genau 64 Hex-Zeichen, klein. */
    public static function deviceSource(string $s): bool
    {
        return preg_match(Limits::DEVICE_SOURCE_PATTERN, $s) === 1;
    }

    /**
     * Prüft complete_before eines Vorgeschichte-Tags: YYYY-MM-DD und ein gültiges Kalenderdatum; die Zukunft ist erlaubt
     * (sie wirkt beim Speichern nur bis heute). Ein fehlendes Feld prüft der Aufrufer nicht.
     */
    public static function legacyCompleteBefore(mixed $s): ?string
    {
        if (!self::matches(Limits::LEGACY_DATE_PATTERN, $s)) {
            return 'Format YYYY-MM-DD erwartet';
        }
        if (!self::validDate((int) substr($s, 0, 4), (int) substr($s, 5, 2), (int) substr($s, 8, 2))) {
            return 'kein gültiges Datum';
        }
        return null;
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
