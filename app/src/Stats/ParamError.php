<?php

declare(strict_types=1);

namespace Tokenlore\Stats;

use InvalidArgumentException;

// Ungültiger Abfrageparameter (wie paramError im Go-Server). Der Eingabewert steht nie in der Meldung.
// Handler antworten mit 400 {"error": Meldung, "path": Parametername}.
final class ParamError extends InvalidArgumentException
{
    public function __construct(public readonly string $path, string $message)
    {
        parent::__construct($message);
    }
}
