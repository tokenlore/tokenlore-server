<?php

declare(strict_types=1);

namespace Tokenlore\Config;

use InvalidArgumentException;

// Ungültige Server-Einstellung (ServerSettings::save): deutscher Text und das betroffene Feld, damit die API
// den Fehler beim richtigen Eingabefeld zeigt (path).
final class SettingError extends InvalidArgumentException
{
    public function __construct(string $message, public readonly string $field)
    {
        parent::__construct($message);
    }
}
