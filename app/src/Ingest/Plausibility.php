<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

use Tokenlore\Db\Database;

// Markiert Sitzungen mit auffällig vielen Anfragen, lehnt aber nichts ab (plausibility.go).
final class Plausibility
{
    // Standardwerte der Tabelle settings, falls dem Nutzer die Zeile fehlt.
    private const DEFAULT_PER_SECOND = 50;
    private const DEFAULT_PER_MINUTE = 500;

    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Gezählt werden alle gespeicherten Anfragen der Sitzung (Subagenten tragen dieselbe session_id) je Sekunde und
     * je Minute in UTC (ts in Millisekunden, Kalendergrenzen). Ab flag_per_second bzw. flag_per_minute des Nutzers
     * (Zahl ≥ Grenze) wird flagged gesetzt, Grund '≥50/s' bzw. '≥500/min'; bei beiden gewinnt die Sekunde.
     * Eine gesetzte Markierung wird nie entfernt. Fehlt die Sitzungszeile noch, wird sie ohne device_id angelegt;
     * die Zeile eines anderen Benutzers bleibt unberührt (Store übergibt nur eigene Sitzungen).
     * Zurück kommen alle aktuell markierten Sitzungen unter den geprüften (neu oder schon vorher), sortiert.
     * Läuft in der Transaktion des Aufrufers (Store), öffnet selbst keine.
     *
     * @param list<string> $sessionIds
     * @return list<string>
     */
    public function flag(int $uid, array $sessionIds): array
    {
        $ids = array_values(array_unique(array_map('strval', $sessionIds)));
        if ($ids === []) {
            return [];
        }
        sort($ids, SORT_STRING);
        // Als JSON-Liste übergeben (json_each): keine Grenze für die Zahl der Platzhalter.
        $json = json_encode($ids, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pdo = $this->db->pdo();
        $st = $pdo->prepare(<<<'SQL'
            insert into sessions (user_id, session_id, flagged, flag_reason)
            select :uid, id, 1, reason from (
              select i.value as id,
                     case when coalesce((select max(c) from (select count(*) c from requests
                                          where user_id = :uid and session_id = i.value group by ts / 1000)), 0) >= cfg.ps
                            then '≥' || cfg.ps || '/s'
                          when coalesce((select max(c) from (select count(*) c from requests
                                          where user_id = :uid and session_id = i.value group by ts / 60000)), 0) >= cfg.pm
                            then '≥' || cfg.pm || '/min'
                     end as reason
                from json_each(:ids) i
                cross join (select coalesce((select flag_per_second from settings where user_id = :uid), :dps) as ps,
                                   coalesce((select flag_per_minute from settings where user_id = :uid), :dpm) as pm) cfg
            ) where reason is not null
            on conflict (session_id) do update set flagged = 1, flag_reason = excluded.flag_reason
              where sessions.user_id = excluded.user_id
            SQL);
        $st->bindValue(':uid', $uid, \PDO::PARAM_INT);
        $st->bindValue(':ids', $json);
        $st->bindValue(':dps', self::DEFAULT_PER_SECOND, \PDO::PARAM_INT);
        $st->bindValue(':dpm', self::DEFAULT_PER_MINUTE, \PDO::PARAM_INT);
        $st->execute();

        $st = $pdo->prepare(
            'select session_id from sessions where user_id = :uid and flagged = 1'
            . ' and session_id in (select value from json_each(:ids)) order by session_id',
        );
        $st->bindValue(':uid', $uid, \PDO::PARAM_INT);
        $st->bindValue(':ids', $json);
        $st->execute();
        return array_map('strval', $st->fetchAll(\PDO::FETCH_COLUMN));
    }
}
