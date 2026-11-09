<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

// Der Besitznachweis des Signaturschlüssels wurde schon einmal angenommen (gleicher Schlüssel, gleicher Code, etwa nach
// erneuter Vergabe des Codes). Antwort 400 mit path sign_public_key_proof; nichts wird geändert, der Code bleibt gültig.
final class ProofReused extends \RuntimeException
{
    /** @param int $userId Benutzer des Codes (für das Sicherheitsprotokoll) */
    public function __construct(public readonly int $userId)
    {
        parent::__construct('Besitznachweis wurde schon verwendet; bitte einen neuen Code anfordern');
    }
}
