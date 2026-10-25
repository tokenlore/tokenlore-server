<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

// Gerät oder Schlüssel wurde gesperrt (oder gehört nicht dem Nutzer), bevor das Paket gespeichert war (ErrDeviceRevoked).
final class DeviceRevoked extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('Gerät gesperrt');
    }
}
