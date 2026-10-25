<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

// Notfall-Zugang abgelehnt: Datei fehlt, ist zu alt, zu groß, kein reguläres File, oder Datei und Code passen
// nicht zu einem ausgegebenen, gültigen Code. Bewusst ein Text für alle Fälle. Handler antworten mit 403.
final class RecoveryDenied extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('Notfall-Datei fehlt oder passt nicht');
    }
}
