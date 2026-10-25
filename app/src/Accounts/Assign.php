<?php

declare(strict_types=1);

namespace Tokenlore\Accounts;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use Tokenlore\Db\Database;
use Tokenlore\Protocol\Limits;
use Tokenlore\Stats\Stats;
use Tokenlore\Util\Sql;
use Tokenlore\Util\Time;

// Manuelle Zuordnung von Anfragen ohne Konto (wie internal/accounts/assign.go). Jede Zuordnung ist ein Datensatz
// in account_assignments und lässt sich rückgängig machen; maßgeblich ist der lokale Tag der Arbeit.
final class Assign
{
    /** Größte Zahl lokaler Tage (inklusive) einer Zuordnung. */
    public const MAX_RANGE_DAYS = 3660;
    private const MIN_DATE = '2024-01-01';

    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Prüft den Datumsbereich (JJJJ-MM-TT, ab 2024-01-01, from <= to, höchstens 3660 Tage) und liefert die beiden
     * Tage als Unix-Sekunden (Mitternacht UTC), sonst null.
     *
     * @return array{0:int,1:int}|null
     */
    public static function parseRange(string $from, string $to): ?array
    {
        $f = self::parseDate($from);
        $t = self::parseDate($to);
        if ($f === null || $t === null || $f < (int) self::parseDate(self::MIN_DATE) || $t < $f) {
            return null;
        }
        if (intdiv($t - $f, 86400) + 1 > self::MAX_RANGE_DAYS) {
            return null;
        }
        return [$f, $t];
    }

    /**
     * Ordnet die Anfragen ohne Konto des Geräts, deren lokaler Arbeitstag in [from, to] liegt, dem Konto zu.
     * Mit $dryRun wird nur gezählt (Zuordnung 0). Ohne betroffene Anfragen entsteht keine Zuordnung (Zuordnung 0).
     * Schreibend läuft alles in einer Schreibtransaktion: gleichzeitige Zuordnungen laufen nacheinander, und keine
     * Anfrage gehört zwei Zuordnungen.
     *
     * @return array{0:int,1:int} Zuordnungs-ID und Zahl der Anfragen
     * @throws AccountError
     */
    public function assign(int $uid, int $deviceId, string $from, string $to, string $accountId, bool $dryRun, int $now): array
    {
        $range = self::parseRange($from, $to) ?? throw AccountError::invalid();
        if (preg_match(Limits::ID_PATTERN, $accountId) !== 1) {
            throw AccountError::invalid();
        }
        return $this->db->tx(static function (PDO $pdo) use ($uid, $deviceId, $from, $to, $accountId, $dryRun, $now, $range): array {
            if (Sql::run($pdo, 'select 1 from devices where id = ? and user_id = ?', [$deviceId, $uid])->fetchColumn() === false
                || Sql::run($pdo, 'select 1 from accounts where user_id = ? and account_id = ?', [$uid, $accountId])->fetchColumn() === false) {
                throw AccountError::notFound();
            }
            // Das Zeitfenster (ein Tag Spielraum für den Versatz von höchstens ±14 h) lässt einen Index greifen.
            $cond = 'r.user_id = ? and r.device_id = ? and r.account_id is null and r.ts >= ? and r.ts < ? and '
                . Stats::LOCAL_DAY . ' between ? and ?';
            $args = [$uid, $deviceId, ($range[0] - 86400) * 1000, ($range[1] + 2 * 86400) * 1000, $from, $to];
            $n = (int) Sql::run($pdo, "select count(*) from requests r where $cond", $args)->fetchColumn();
            if ($dryRun || $n === 0) {
                return [0, $n];
            }
            Sql::run($pdo, 'insert into account_assignments (user_id, device_id, local_from, local_to, account_id, created_at)
                values (?, ?, ?, ?, ?, ?)', [$uid, $deviceId, $from, $to, $accountId, $now]);
            $id = (int) $pdo->lastInsertId();
            $n = Sql::run($pdo, "update requests as r set account_id = ?, assignment_id = ? where $cond",
                array_merge([$accountId, $id], $args))->rowCount();
            return [$id, $n];
        }, !$dryRun);
    }

    /**
     * Macht eine Zuordnung rückgängig: nur ihre Anfragen verlieren Konto und Zuordnung.
     *
     * @return int Zahl der Anfragen
     * @throws AccountError
     */
    public function undo(int $uid, int $assignmentId, int $now): int
    {
        return $this->db->tx(static function (PDO $pdo) use ($uid, $assignmentId, $now): int {
            $id = Sql::run($pdo, 'select id from account_assignments where id = ? and user_id = ? and undone_at is null',
                [$assignmentId, $uid])->fetchColumn();
            if ($id === false) {
                throw AccountError::notFound();
            }
            $n = Sql::run($pdo, 'update requests set account_id = null, assignment_id = null where user_id = ? and assignment_id = ?',
                [$uid, (int) $id])->rowCount();
            Sql::run($pdo, 'update account_assignments set undone_at = ? where id = ?', [$now, (int) $id]);
            return $n;
        });
    }

    /**
     * Die Zuordnungen des Nutzers, neueste zuerst (höchstens 500), mit aktueller Zahl der Anfragen.
     *
     * @return list<array<string,mixed>> Felder wie GET /api/accounts/assignments
     */
    public function list(int $uid): array
    {
        $out = [];
        foreach (Sql::run($this->db->pdo(), "select a.id, a.device_id, coalesce(d.name, '') as device_name, a.local_from, a.local_to,
                    a.account_id,
                    (select count(*) from requests r where r.user_id = a.user_id and r.assignment_id = a.id) as n,
                    a.created_at, a.undone_at
                  from account_assignments a
                  left join devices d on d.id = a.device_id and d.user_id = a.user_id
                 where a.user_id = ? order by a.id desc limit 500", [$uid]) as $a) {
            $out[] = [
                'id' => (int) $a['id'],
                'device_id' => (int) $a['device_id'],
                'device_name' => $a['device_name'],
                'from' => $a['local_from'],
                'to' => $a['local_to'],
                'account_id' => $a['account_id'],
                'requests' => (int) $a['n'],
                'created_at' => Time::isoSec((int) $a['created_at']),
                'undone_at' => $a['undone_at'] === null ? null : Time::isoSec((int) $a['undone_at']),
            ];
        }
        return $out;
    }

    /** JJJJ-MM-TT streng wie time.Parse("2006-01-02") als Unix-Sekunden (Mitternacht UTC), sonst null. */
    private static function parseDate(string $s): ?int
    {
        if (preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})\z/', $s, $m) !== 1 || !checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            return null;
        }
        return (new DateTimeImmutable($s, new DateTimeZone('UTC')))->getTimestamp();
    }
}
