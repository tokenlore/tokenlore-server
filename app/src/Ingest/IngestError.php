<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

// Ungültiges Lieferpaket (ValidationError im Go-Server): Pfad des ersten schlechten Felds und feste Meldung.
// Meldungen nennen nur den Feldpfad und was daran falsch ist, nie den Wert. $reason (leer: keiner) kennzeichnet einen Fall,
// den das Plugin erkennen soll, unabhängig vom Wortlaut der Meldung.
final class IngestError extends \RuntimeException
{
    /** Signatur passt zu keinem Schlüssel des Geräts: meist hat ein anderes Gerät ihn übernommen (protocol/doc.md). */
    public const REASON_SIGN_KEY_UNKNOWN = 'sign_key_unknown';

    public function __construct(
        public readonly string $path,
        public readonly string $msg,
        public readonly int $status = 400,
        public readonly string $reason = '',
    ) {
        parent::__construct($path === '' ? $msg : $path . ': ' . $msg);
    }
}
