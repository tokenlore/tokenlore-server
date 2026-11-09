<?php

declare(strict_types=1);

namespace Tokenlore\Protocol;

// Grenzen und Muster des Lieferformats, übernommen aus https://github.com/tokenlore/tokenlore/blob/main/protocol/limits.go und validate.go.
// Go-Name MaxBatchBytes heißt hier MAX_BATCH_BYTES. Muster enden mit \z, weil $ in PCRE auch vor einem
// abschließenden Zeilenumbruch passt, das Go-Muster aber nicht.
final class Limits
{
    // Grenzen eines Lieferpakets (limits.go).
    public const MAX_BATCH_BYTES = 1 << 20;
    public const MAX_REQUESTS_PER_BATCH = 2000;
    public const MAX_EXTRA_FIELDS = 16;
    public const MAX_EXTRA_STRING = 64;
    public const MAX_EMAIL_LEN = 254;
    public const MAX_SESSIONS_PER_BATCH = 10_000;
    public const MAX_DEVICE_NAME = 64;
    public const MAX_TZ_LEN = 64;
    /** Höchstzahl der Vorgeschichte-Tage (legacy_days) je Paket. */
    public const MAX_LEGACY_LIST = 10_000;
    public const MAX_LEGACY_NUMBER = 1_000_000_000_000;
    /** Höchstzahl der Modelle je Vorgeschichte-Tag. */
    public const MAX_LEGACY_MODELS = 64;

    /** Protokollversion jedes Lieferpakets (Feld v). */
    public const PROTOCOL_VERSION = 2;

    // Signierte Zeile (Abschnitt „Hülle“ und „Inhaltszeile“ in protocol/doc.md).
    /** Höchstlänge der Inhaltszeile z in Byte (UTF-8, dekodierter Wert). */
    public const MAX_LINE_BYTES = 8192;
    /** utc_offset_min: höchstens ±14 h in Minuten. */
    public const MAX_UTC_OFFSET_MIN = 840;
    /** usage: höchstens so viele Ebenen (usage selbst ist Ebene 1), Werte insgesamt und Einträge je Liste. */
    public const USAGE_MAX_DEPTH = 4;
    public const USAGE_MAX_VALUES = 256;
    public const USAGE_MAX_LIST = 64;

    /** Uhrabweichung, die ein Zeitstempel in der Zukunft haben darf (Go: MaxFutureSkew, 5 Minuten), in Millisekunden. */
    public const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

    /** Älteste Plugin-Version, die der Server annimmt (x.y.z); GET /api/plugin/info nennt sie. */
    public const MIN_PLUGIN_VERSION = '0.6.0';

    /** Öffentlicher Ed25519-Signaturschlüssel beim Koppeln: 32 Byte, als Base64 mit Auffüllung genau 44 Zeichen. */
    public const SIGN_KEY_BYTES = 32;
    /** Höchstzahl früherer Signaturschlüssel (sign_public_keys_previous) je Koppeln. */
    public const MAX_SIGN_KEYS_PREVIOUS = 16;
    /**
     * Höchstzahl verschiedener Signaturschlüssel je Gerät (aktuelle und frühere zusammen). Die Datenannahme prüft jede
     * Zeile gegen alle Schlüssel des Geräts; ohne Grenze wüchse die Rechenzeit einer Lieferung mit jedem Koppeln. Ein
     * Plugin meldet höchstens 1 + 16 Schlüssel. Der zuletzt gemeldete aktuelle Schlüssel bleibt immer; darüber fallen
     * die ältesten übrigen weg, auch nach dem Zusammenlegen (Devices::capSignKeys). 2000 Zeilen kosten damit im schlechtesten Fall
     * etwa 32 statt einer Prüfung je Zeile (gemessen gut 2 s statt 0,1 s).
     */
    public const MAX_SIGN_KEYS_PER_DEVICE = 32;

    public const MODEL_PATTERN ='/^[A-Za-z0-9._-]{1,64}\z/';

    /** Geräteschlüssel: tl_dk_ + 32 Byte base64url ohne Auffüllung. */
    public const DEVICE_KEY_PATTERN = '/^tl_dk_[A-Za-z0-9_-]{43}\z/';

    /** Kennung des Rechners beim Koppeln (device_source): Hex-HMAC-SHA256, genau 64 Zeichen, klein. */
    public const DEVICE_SOURCE_PATTERN = '/^[0-9a-f]{64}\z/';

    // Feldgrenzen (validate.go).
    public const MAX_ID_LEN = 128;
    public const MAX_SHORT_TEXT = 32;
    public const MAX_TOOLS = 64;
    public const MAX_TOKENS_PER_FIELD = 100_000_000;
    public const MAX_COUNT_PER_FIELD = 10_000;

    public const ID_PATTERN = '/^[A-Za-z0-9._:-]{1,128}\z/';
    public const TOOL_PATTERN = '/^[A-Za-z0-9._:-]{1,128}\z/';
    /** stop_reason, effort und entrypoint. */
    public const STOP_PATTERN = '/^[A-Za-z0-9_.-]{1,32}\z/';
    public const VERSION_PATTERN = '/^[0-9A-Za-z.+-]{1,32}\z/';
    public const EXTRA_KEY = '/^[A-Za-z0-9_]{1,64}\z/';
    public const LEGACY_DATE_PATTERN = '/^[0-9]{4}-[0-9]{2}-[0-9]{2}\z/';
    /** ts einer Inhaltszeile: immer UTC mit Z, Bruchteile höchstens 9 Stellen. */
    public const TS_PATTERN = '/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z\z/';

    /** Frühester zulässiger Zeitstempel (Go: Earliest, 2024-01-01T00:00:00Z) als Unix-Sekunden und als Datum. */
    public const EARLIEST_UNIX = 1704067200;
    public const EARLIEST_DATE = '2024-01-01';

    // Werte für email_mode (protocol.go).
    public const EMAIL_OFF = 'off';
    public const EMAIL_SHORT = 'short';
    public const EMAIL_FULL = 'full';
}
