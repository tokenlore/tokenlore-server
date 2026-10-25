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
    public const MAX_LEGACY_LIST = 10_000;
    public const MAX_LEGACY_NUMBER = 1_000_000_000_000;

    /** Uhrabweichung, die ein Zeitstempel in der Zukunft haben darf (Go: MaxFutureSkew, 5 Minuten), in Millisekunden. */
    public const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

    public const MODEL_PATTERN = '/^[A-Za-z0-9._-]{1,64}\z/';

    /** Geräteschlüssel: tl_dk_ + 32 Byte base64url ohne Auffüllung. */
    public const DEVICE_KEY_PATTERN = '/^tl_dk_[A-Za-z0-9_-]{43}\z/';

    // Feldgrenzen (validate.go).
    public const MAX_ID_LEN = 128;
    public const MAX_SHORT_TEXT = 32;
    public const MAX_TOOLS = 64;
    public const MAX_TOKENS_PER_FIELD = 100_000_000;
    public const MAX_COUNT_PER_FIELD = 10_000;

    public const ID_PATTERN = '/^[A-Za-z0-9._:-]{1,128}\z/';
    public const TOOL_PATTERN = '/^[A-Za-z0-9._:-]{1,128}\z/';
    public const STOP_PATTERN = '/^[A-Za-z0-9_.-]{1,32}\z/';
    public const VERSION_PATTERN = '/^[0-9A-Za-z.+-]{1,32}\z/';
    public const EXTRA_KEY = '/^[A-Za-z0-9_]{1,64}\z/';
    public const PROJECT_PATTERN = '/^[0-9a-f]{64}\z/';
    public const LEGACY_DATE_PATTERN = '/^[0-9]{4}-[0-9]{2}-[0-9]{2}\z/';

    /** Frühester zulässiger Zeitstempel (Go: Earliest, 2024-01-01T00:00:00Z) als Unix-Sekunden und als Datum. */
    public const EARLIEST_UNIX = 1704067200;
    public const EARLIEST_DATE = '2024-01-01';

    // Werte für email_mode (protocol.go).
    public const EMAIL_OFF = 'off';
    public const EMAIL_SHORT = 'short';
    public const EMAIL_FULL = 'full';
}
