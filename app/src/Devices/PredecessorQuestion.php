<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

// Frage nach dem Vorgänger beim Koppeln (protocol/doc.md, „Vorgänger“): Der Rechner ist neu, sein Konfigurationsordner
// stammt aber von Gerät A desselben Benutzers, und für das Paar gibt es noch keine Antwort. Antwort 409
// {"error":"predecessor_question","predecessor":{…},"recommended":…}; nichts wird geändert, der Code bleibt gültig.
final class PredecessorQuestion extends \RuntimeException
{
    /**
     * @param int $userId Benutzer des Codes (für das Sicherheitsprotokoll)
     * @param array{device_id:int, name:string, last_seen_at:string|null, os:string, arch:string, recent:bool, sign_key_match:bool} $predecessor
     *        Angaben zu A, Feldnamen wie im Protokoll
     * @param 'same'|'new' $recommended
     */
    public function __construct(
        public readonly int $userId,
        public readonly array $predecessor,
        public readonly string $recommended,
    ) {
        parent::__construct('predecessor_question');
    }
}
