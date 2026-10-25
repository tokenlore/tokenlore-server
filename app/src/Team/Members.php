<?php

declare(strict_types=1);

namespace Tokenlore\Team;

use PDO;
use Tokenlore\Auth\AuthError;
use Tokenlore\Auth\Users;
use Tokenlore\Db\Database;

// Mitgliederliste und die Änderungen, die den letzten Admin entfernen könnten (Rolle entziehen, sperren).
// Der Schutz steckt in derselben UPDATE-Anweisung wie die Änderung: zwei Admins, die sich gleichzeitig
// gegenseitig herabstufen, lassen so trotzdem einen übrig. Aktiv heißt: Rolle admin und nicht gesperrt
// (wie Users::adminCount). Alles andere (anlegen, Passwort, entsperren) macht Users.
final class Members
{
    /** Bedingung „die Zeile ist danach nicht mehr aktiver Admin, und es bleibt einer“. */
    private const KEEPS_AN_ADMIN = "(role <> 'admin' or disabled_at is not null
        or (select count(*) from users where role = 'admin' and disabled_at is null) > 1)";

    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Alle Konten für die Verwaltung, nach ID. devices zählt die nicht widerrufenen Geräte, last_seen_at ist
     * die letzte Datenlieferung irgendeines Geräts. Zeiten als RFC 3339 in UTC.
     *
     * @return list<array{id:int,username:string,role:string,disabled:bool,created_at:string,devices:int,last_seen_at:?string}>
     */
    public function list(): array
    {
        $rows = $this->db->pdo()->query('select u.id, u.username, u.role, u.disabled_at, u.created_at,
                (select count(*) from devices d where d.user_id = u.id and d.revoked_at is null) as devices,
                (select max(d.last_seen_at) from devices d where d.user_id = u.id) as last_seen_at
            from users u order by u.id')->fetchAll();
        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'id' => (int) $row['id'],
                'username' => (string) $row['username'],
                'role' => (string) $row['role'],
                'disabled' => $row['disabled_at'] !== null,
                'created_at' => self::iso((int) $row['created_at']),
                'devices' => (int) $row['devices'],
                'last_seen_at' => $row['last_seen_at'] === null ? null : self::iso((int) $row['last_seen_at']),
            ];
        }
        return $out;
    }

    public function exists(int $id): bool
    {
        $st = $this->db->pdo()->prepare('select 1 from users where id = ?');
        $st->execute([$id]);
        return $st->fetchColumn() !== false;
    }

    /** @return list<int> alle Konten (auch gesperrte), für die Team-Summe */
    public function ids(): array
    {
        return array_map('intval', $this->db->pdo()->query('select id from users order by id')->fetchAll(PDO::FETCH_COLUMN));
    }

    /**
     * Setzt die Rolle. Fehler: AuthError INVALID_ROLE oder UNKNOWN_USER, LastAdminError beim letzten aktiven Admin.
     * Die Sitzungen bleiben: die Rolle liest die Middleware bei jeder Anfrage neu.
     */
    public function setRole(int $id, string $role): void
    {
        if (!in_array($role, Users::ROLES, true)) {
            throw AuthError::of(AuthError::INVALID_ROLE);
        }
        $sql = $role === 'admin'
            ? "update users set role = 'admin' where id = ?"
            : "update users set role = ? where id = ? and " . self::KEEPS_AN_ADMIN;
        $args = $role === 'admin' ? [$id] : [$role, $id];
        $this->guarded($id, static function (PDO $pdo) use ($sql, $args): bool {
            $st = $pdo->prepare($sql);
            $st->execute($args);
            return $st->rowCount() > 0;
        });
    }

    /**
     * Sperrt das Konto und beendet seine Sitzungen (wie Users::disable; ein erneutes Sperren behält den ersten
     * Zeitpunkt). Fehler: AuthError UNKNOWN_USER, LastAdminError beim letzten aktiven Admin.
     */
    public function disable(int $id, ?int $now = null): void
    {
        $now ??= time();
        $this->guarded($id, static function (PDO $pdo) use ($id, $now): bool {
            $st = $pdo->prepare('update users set disabled_at = coalesce(disabled_at, ?) where id = ? and ' . self::KEEPS_AN_ADMIN);
            $st->execute([$now, $id]);
            if ($st->rowCount() === 0) {
                return false;
            }
            $pdo->prepare('delete from web_sessions where user_id = ?')->execute([$id]);
            return true;
        });
    }

    /**
     * Führt $change in einer Schreibtransaktion aus. Ändert sie keine Zeile, gibt es das Konto nicht oder es ist
     * der letzte aktive Admin. Der Fehler fällt erst nach der Transaktion (geschrieben ist dann nichts; bei einer
     * Exception in der Transaktion rollte Database::tx ebenso zurück).
     *
     * @param callable(PDO): bool $change
     */
    private function guarded(int $id, callable $change): void
    {
        $result = $this->db->tx(static function (PDO $pdo) use ($id, $change): string {
            if ($change($pdo)) {
                return 'ok';
            }
            $st = $pdo->prepare('select 1 from users where id = ?');
            $st->execute([$id]);
            return $st->fetchColumn() === false ? 'unknown' : 'last_admin';
        });
        if ($result === 'unknown') {
            throw AuthError::of(AuthError::UNKNOWN_USER);
        }
        if ($result === 'last_admin') {
            throw new LastAdminError();
        }
    }

    /** Unix-Sekunden als RFC 3339 in UTC (2026-10-25T08:00:00Z). */
    public static function iso(int $sec): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $sec);
    }
}
