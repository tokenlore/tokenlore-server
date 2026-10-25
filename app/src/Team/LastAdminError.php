<?php

declare(strict_types=1);

namespace Tokenlore\Team;

// Die Änderung ließe keinen aktiven Admin übrig (Rolle entziehen oder sperren). Handler antworten mit 409.
final class LastAdminError extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('Der letzte Admin kann nicht entfernt werden');
    }
}
