<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

// Falscher, abgelaufener, benutzter oder durch Fehlversuche erschöpfter Kopplungscode (nicht unterscheidbar).
final class BadCodeException extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('Code ungültig');
    }
}
