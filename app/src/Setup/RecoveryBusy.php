<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

// Es sind schon so viele gültige Notfall-Codes offen, wie die Tabelle höchstens hält, und keiner ist alt genug,
// um ihn zu verdrängen. Handler antworten mit 429 und Retry-After ($retryAfter, ganze Sekunden, mindestens 1).
final class RecoveryBusy extends \RuntimeException
{
    public function __construct(public readonly int $retryAfter)
    {
        parent::__construct('Zu viele offene Notfall-Codes, bitte später erneut versuchen');
    }
}
