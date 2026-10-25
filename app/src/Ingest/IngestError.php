<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

// Ungültiges Lieferpaket (ValidationError im Go-Server): Pfad des ersten schlechten Felds und feste Meldung.
// Meldungen nennen nur den Feldpfad und was daran falsch ist, nie den Wert.
final class IngestError extends \RuntimeException
{
    public function __construct(
        public readonly string $path,
        public readonly string $msg,
        public readonly int $status = 400,
    ) {
        parent::__construct($path === '' ? $msg : $path . ': ' . $msg);
    }
}
