<?php

declare(strict_types=1);

namespace Tokenlore\Http;

// Schnittstelle zur Sitzungsprüfung; die Umsetzung liefert die Sitzungsverwaltung (Task 5).
interface SessionResolver
{
    /**
     * Prüft ein Sitzungs-Token (Form ist schon geprüft) zum Zeitpunkt $now (Unix-Sekunden).
     * null: unbekannt, abgelaufen oder Konto gesperrt.
     *
     * @return array{uid:int,csrf:string,role:string}|null
     */
    public function user(string $token, int $now): ?array;
}
