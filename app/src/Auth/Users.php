<?php

declare(strict_types=1);

namespace Tokenlore\Auth;

use Closure;
use PDO;
use PDOException;
use Tokenlore\Db\Database;

// Konten mit Rollen (admin, member) und Sperre (disabled_at), wie internal/auth/users.go plus Rollen.
// Fehler kommen als AuthError; den Schutz des letzten Admins prüft die Verwaltung (adminCount).
final class Users
{
    /** Mindestlänge in Zeichen (nicht Bytes). */
    public const MIN_PASSWORD_LEN = 12;

    public const ROLES = ['admin', 'member'];

    private const NAME_PATTERN = '/^[a-z0-9._-]{3,32}\z/';

    private readonly Closure $clock;

    /** @param (callable(): int)|null $clock Unix-Sekunden für disabled_at (Standard: time()) */
    public function __construct(private readonly Database $db, ?callable $clock = null)
    {
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
    }

    /** Legt Nutzer und Standard-Einstellungen in einer Transaktion an und liefert die ID. */
    public function create(string $username, string $pw, string $role = 'member'): int
    {
        if (!preg_match(self::NAME_PATTERN, $username)) {
            throw AuthError::of(AuthError::INVALID_USERNAME);
        }
        self::checkRole($role);
        self::checkLength($pw);
        $hash = Password::hash($pw);
        $salt = random_bytes(32);
        return $this->db->tx(static function (PDO $pdo) use ($username, $hash, $salt, $role): int {
            $st = $pdo->prepare('insert into users (username, pw_hash, source_salt, role) values (?, ?, ?, ?)');
            $st->bindValue(1, $username);
            $st->bindValue(2, $hash);
            $st->bindValue(3, $salt, PDO::PARAM_LOB);
            $st->bindValue(4, $role);
            try {
                $st->execute();
            } catch (PDOException $e) {
                // SQLITE_CONSTRAINT (19) beim eindeutigen Namen; Database::tx rollt zurück.
                if (($e->errorInfo[1] ?? null) === 19 && str_contains($e->getMessage(), 'users.username')) {
                    throw AuthError::of(AuthError::USERNAME_TAKEN);
                }
                throw $e;
            }
            $id = (int) $pdo->lastInsertId();
            $pdo->prepare('insert into settings (user_id) values (?)')->execute([$id]);
            return $id;
        });
    }

    /** @return array{id:int,username:string,role:string,disabled_at:?int,created_at:int}|null */
    public function byId(int $id): ?array
    {
        $st = $this->db->pdo()->prepare('select id, username, role, disabled_at, created_at from users where id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        if ($row === false) {
            return null;
        }
        return [
            'id' => (int) $row['id'],
            'username' => (string) $row['username'],
            'role' => (string) $row['role'],
            'disabled_at' => $row['disabled_at'] === null ? null : (int) $row['disabled_at'],
            'created_at' => (int) $row['created_at'],
        ];
    }

    public function setRole(int $id, string $role): void
    {
        self::checkRole($role);
        $this->update('update users set role = ? where id = ?', [$role, $id]);
    }

    /** Sperrt das Konto und beendet alle seine Sitzungen; ein erneutes Sperren behält den ersten Zeitpunkt. */
    public function disable(int $id): void
    {
        $this->updateAndEndSessions($id, 'update users set disabled_at = coalesce(disabled_at, ?) where id = ?', [($this->clock)(), $id]);
    }

    public function enable(int $id): void
    {
        $this->update('update users set disabled_at = null where id = ?', [$id]);
    }

    /** Setzt das Passwort neu (Admin), hebt die Sperre nach Fehlversuchen auf und beendet alle Sitzungen. */
    public function resetPassword(int $id, string $pw): void
    {
        self::checkLength($pw);
        $hash = Password::hash($pw);
        $this->updateAndEndSessions($id, 'update users set pw_hash = ?, failed_logins = 0, locked_until = null where id = ?', [$hash, $id]);
    }

    /** Admins, die nicht gesperrt sind (nur sie können verwalten). */
    public function adminCount(): int
    {
        return (int) $this->db->pdo()->query("select count(*) from users where role = 'admin' and disabled_at is null")->fetchColumn();
    }

    /** Wirft PASSWORD_TOO_SHORT, wenn $pw kürzer als MIN_PASSWORD_LEN Zeichen ist. */
    public static function checkLength(string $pw): void
    {
        if (mb_strlen($pw, 'UTF-8') < self::MIN_PASSWORD_LEN) {
            throw AuthError::of(AuthError::PASSWORD_TOO_SHORT);
        }
    }

    private static function checkRole(string $role): void
    {
        if (!in_array($role, self::ROLES, true)) {
            throw AuthError::of(AuthError::INVALID_ROLE);
        }
    }

    /**
     * Ändert die Zeile des Nutzers $id per $sql und löscht in derselben Transaktion seine Sitzungen.
     * Unbekannter Nutzer: UNKNOWN_USER, es bleibt alles, wie es war (Database::tx rollt zurück).
     *
     * @param list<int|string> $args
     */
    private function updateAndEndSessions(int $id, string $sql, array $args): void
    {
        $this->db->tx(static function (PDO $pdo) use ($id, $sql, $args): void {
            $st = $pdo->prepare($sql);
            $st->execute($args);
            if ($st->rowCount() === 0) {
                throw AuthError::of(AuthError::UNKNOWN_USER);
            }
            $pdo->prepare('delete from web_sessions where user_id = ?')->execute([$id]);
        });
    }

    /** @param list<int|string> $args */
    private function update(string $sql, array $args): void
    {
        $st = $this->db->pdo()->prepare($sql);
        $st->execute($args);
        if ($st->rowCount() === 0) {
            throw AuthError::of(AuthError::UNKNOWN_USER);
        }
    }
}
