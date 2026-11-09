<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

// Der Kopplungscode gilt für ein bestehendes Gerät, die Kennung des Rechners (device_source) gehört aber einem
// anderen Gerät desselben Benutzers. Antwort 409 {"error":"source_taken"}; nichts wird geändert.
final class SourceTaken extends \RuntimeException
{
    /** @param int $userId Benutzer des Codes (für das Sicherheitsprotokoll) */
    public function __construct(public readonly int $userId)
    {
        parent::__construct('source_taken');
    }
}
