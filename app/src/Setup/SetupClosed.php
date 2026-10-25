<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

// Die Einrichtung ist schon abgeschlossen (es gibt ein Konto); sie lässt sich nicht noch einmal ausführen.
final class SetupClosed extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('Die Einrichtung ist schon abgeschlossen.');
    }
}
