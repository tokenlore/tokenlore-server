<?php

declare(strict_types=1);

namespace Tokenlore\Stats;

use PDO;
use Tokenlore\Db\Database;
use Tokenlore\Util\Sql;
use Tokenlore\Util\Time;

// Listen je Nutzer (wie internal/stats/lists.go): Modelle, Konten, Anfragen ohne Konto je Gerät, Summen je Gerät.
// Die Felder entsprechen den JSON-Antworten von /api/models, /api/accounts und /api/accounts/unknown.
final class Lists
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Modelle mit Anfragen und Token im Filter, meiste Token zuerst.
     *
     * @param array<string,mixed> $f Filter wie Stats::NO_FILTER
     * @return list<array{model:string,requests:int,tokens:int,first:string,last:string}>
     */
    public function models(int $uid, array $f): array
    {
        [$conds, $args] = Stats::filterConds($f);
        $where = implode(' and ', array_merge(['r.user_id = ?'], $conds));
        $out = [];
        foreach (Sql::run($this->db->pdo(), 'select r.model, count(*) as n, sum(' . Stats::TOKENS . ") as t, min(r.ts) as a, max(r.ts) as b
                from requests r where $where group by r.model order by t desc, r.model", array_merge([$uid], $args)) as $m) {
            $out[] = [
                'model' => $m['model'], 'requests' => (int) $m['n'], 'tokens' => (int) $m['t'],
                'first' => Time::isoMs((int) $m['a']), 'last' => Time::isoMs((int) $m['b']),
            ];
        }
        return $out;
    }

    /**
     * Alle Konten des Nutzers mit ihren Anfragen im Filter (Konto-Filter bleiben außen vor) und die Anfragen
     * ohne Konto getrennt zusammengefasst.
     *
     * @param array<string,mixed> $f
     * @return array{accounts: list<array<string,mixed>>, unknown: array{requests:int,sessions:int,tokens:int}}
     */
    public function accounts(int $uid, array $f): array
    {
        $f['account'] = '';
        $f['unknown_account'] = false;
        [$conds, $args] = Stats::filterConds($f);
        $pdo = $this->db->pdo();
        // Die Bedingungen des Filters hängen am Join, damit Konten ohne Anfragen erhalten bleiben.
        $join = $conds === [] ? '' : ' and ' . implode(' and ', $conds);
        $accounts = [];
        foreach (Sql::run($pdo, 'select a.account_id, a.display_name, a.email, count(r.message_id) as n,
                    coalesce(sum(' . Stats::TOKENS . "), 0) as t, min(r.ts) as first, max(r.ts) as last
                  from accounts a
                  left join requests r on r.user_id = a.user_id and r.account_id = a.account_id$join
                 where a.user_id = ?
                 group by a.account_id, a.display_name, a.email
                 order by t desc, a.account_id", array_merge($args, [$uid])) as $a) {
            $accounts[] = [
                'account_id' => $a['account_id'],
                'display_name' => $a['display_name'],
                'email' => $a['email'],
                'requests' => (int) $a['n'],
                'tokens' => (int) $a['t'],
                'first' => $a['first'] === null ? null : Time::isoMs((int) $a['first']),
                'last' => $a['last'] === null ? null : Time::isoMs((int) $a['last']),
            ];
        }
        $where = implode(' and ', array_merge(['r.user_id = ?'], $conds, ['r.account_id is null']));
        $u = Sql::run($pdo, 'select count(*) as n, coalesce(sum(' . Stats::TOKENS . "), 0) as t, count(distinct r.session_id) as s
                from requests r where $where", array_merge([$uid], $args))->fetch(PDO::FETCH_ASSOC);
        // Schlüssel alphabetisch wie eine Go-Map.
        return ['accounts' => $accounts, 'unknown' => ['requests' => (int) $u['n'], 'sessions' => (int) $u['s'], 'tokens' => (int) $u['t']]];
    }

    /**
     * Je Gerät die Anfragen ohne Konto mit erstem und letztem lokalen Tag der Arbeit.
     *
     * @return list<array{device_id:int,device_name:string,requests:int,first_date:string,last_date:string}>
     */
    public function unknownSources(int $uid): array
    {
        $out = [];
        foreach (Sql::run($this->db->pdo(), 'select d.id, d.name, count(*) as n,
                    min(' . Stats::LOCAL_DAY . ') as a, max(' . Stats::LOCAL_DAY . ') as b
                  from requests r
                  join devices d on d.id = r.device_id and d.user_id = r.user_id
                 where r.user_id = ? and r.account_id is null
                 group by d.id, d.name order by d.id', [$uid]) as $s) {
            $out[] = [
                'device_id' => (int) $s['id'], 'device_name' => $s['name'], 'requests' => (int) $s['n'],
                'first_date' => $s['a'], 'last_date' => $s['b'],
            ];
        }
        return $out;
    }

    /**
     * Je Gerät mit Anfragen die Summen über alle Zeiten (für die Geräteliste).
     *
     * @return array<int, array{requests:int,tokens:int,first:string,last:string}> Geräte-ID => Summen
     */
    public function deviceTotals(int $uid): array
    {
        $out = [];
        foreach (Sql::run($this->db->pdo(), 'select r.device_id, count(*) as n, sum(' . Stats::TOKENS . ') as t, min(r.ts) as a, max(r.ts) as b
                from requests r where r.user_id = ? group by r.device_id', [$uid]) as $d) {
            $out[(int) $d['device_id']] = [
                'requests' => (int) $d['n'], 'tokens' => (int) $d['t'],
                'first' => Time::isoMs((int) $d['a']), 'last' => Time::isoMs((int) $d['b']),
            ];
        }
        return $out;
    }
}
