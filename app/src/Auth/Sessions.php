<?php

declare(strict_types=1);

namespace Tokenlore\Auth;

use Closure;
use PDO;
use Tokenlore\Db\Database;
use Tokenlore\Http\SessionResolver;

// Web-Sitzungen wie internal/auth/sessions.go: Anmeldung mit Sperre nach Fehlversuchen, Passwortwechsel,
// Abmelden und Widerruf. In der Datenbank steht nur sha256(token) als BLOB. Gesperrte Konten (disabled_at)
// melden sich nicht an, ihre Sitzungen gelten nicht. Zeiten sind Unix-Sekunden.
final class Sessions implements SessionResolver
{
    /** Absolute Gültigkeit einer Web-Sitzung: 14 Tage. */
    public const TTL = 14 * 24 * 3600;
    /** So viele Fehlversuche sperren das Konto für LOCK_DURATION. */
    public const MAX_FAILED_LOGINS = 10;
    public const LOCK_DURATION = 15 * 60;

    private readonly ?Closure $afterLockCheck;

    /**
     * @param (callable(): void)|null $afterLockCheck Test-Haken zwischen Sperrprüfung und Abschluss
     */
    public function __construct(private readonly Database $db, ?callable $afterLockCheck = null)
    {
        $this->afterLockCheck = $afterLockCheck === null ? null : Closure::fromCallable($afterLockCheck);
    }

    /** sha256(token) als Rohbytes; nur dieser Wert steht in web_sessions.token_hash. */
    public static function hashToken(string $token): string
    {
        return hash('sha256', $token, true);
    }

    /**
     * Prüft die Zugangsdaten und legt eine Sitzung an.
     * Fehler: BAD_CREDENTIALS (unbekannt, falsch oder Konto gesperrt) oder LOCKED (zu viele Fehlversuche).
     *
     * @return array{uid:int,token:string,csrf:string}
     */
    public function login(string $user, string $pw, int $now): array
    {
        $st = $this->db->pdo()->prepare('select id, pw_hash, locked_until, disabled_at from users where username = ?');
        $st->execute([$user]);
        $row = $st->fetch();
        if ($row === false) {
            // Rechenaufwand wie bei einem echten Konto gegen Zeit-Seitenkanäle.
            Password::verify(self::dummyHash(), $pw);
            throw AuthError::of(AuthError::BAD_CREDENTIALS);
        }
        $id = (int) $row['id'];
        $hash = (string) $row['pw_hash'];
        if ($row['disabled_at'] !== null) {
            // Gesperrtes Konto: Antwort und Aufwand wie bei falschem Passwort, nichts wird gezählt.
            Password::verify($hash, $pw);
            throw AuthError::of(AuthError::BAD_CREDENTIALS, $id);
        }
        // Gesperrt nach Fehlversuchen: Passwort nicht prüfen und nicht zählen.
        if ($row['locked_until'] !== null && (int) $row['locked_until'] > $now) {
            throw AuthError::of(AuthError::LOCKED, $id);
        }
        $this->afterLockCheck();
        if (!Password::verify($hash, $pw)) {
            throw $this->countFailure($id, $now);
        }
        $token = self::randomToken();
        $csrf = self::randomToken();
        $refused = $this->db->tx(function (PDO $pdo) use ($id, $hash, $now, $token, $csrf): ?string {
            $refused = self::resetFailures($pdo, $id, $hash, $now);
            if ($refused !== null) {
                return $refused;
            }
            // Abgelaufene Sitzungen aller Konten gesammelt aufräumen (sonst verschwinden sie erst beim nächsten Aufruf).
            $del = $pdo->prepare('delete from web_sessions where expires_at <= ?');
            $del->bindValue(1, $now, PDO::PARAM_INT);
            $del->execute();
            $st = $pdo->prepare('insert into web_sessions (token_hash, user_id, csrf_token, created_at, expires_at) values (?, ?, ?, ?, ?)');
            $st->bindValue(1, self::hashToken($token), PDO::PARAM_LOB);
            $st->bindValue(2, $id, PDO::PARAM_INT);
            $st->bindValue(3, $csrf);
            $st->bindValue(4, $now, PDO::PARAM_INT);
            $st->bindValue(5, $now + self::TTL, PDO::PARAM_INT);
            $st->execute();
            return null;
        });
        if ($refused !== null) {
            throw AuthError::of($refused, $id);
        }
        return ['uid' => $id, 'token' => $token, 'csrf' => $csrf];
    }

    /**
     * Nutzer, CSRF-Token und Rolle zu einem Sitzungs-Token; abgelaufene Sitzungen werden gelöscht.
     *
     * @return array{uid:int,csrf:string,role:string}|null
     */
    public function user(string $token, int $now): ?array
    {
        $st = $this->db->pdo()->prepare('select s.user_id, s.csrf_token, s.expires_at, u.role, u.disabled_at
            from web_sessions s join users u on u.id = s.user_id where s.token_hash = ?');
        $st->bindValue(1, self::hashToken($token), PDO::PARAM_LOB);
        $st->execute();
        $row = $st->fetch();
        if ($row === false || $row['disabled_at'] !== null) {
            return null;
        }
        if ((int) $row['expires_at'] <= $now) {
            $this->logout($token);
            return null;
        }
        return ['uid' => (int) $row['user_id'], 'csrf' => (string) $row['csrf_token'], 'role' => (string) $row['role']];
    }

    /** Löscht die Sitzung; ein unbekanntes Token ist kein Fehler. */
    public function logout(string $token): void
    {
        $st = $this->db->pdo()->prepare('delete from web_sessions where token_hash = ?');
        $st->bindValue(1, self::hashToken($token), PDO::PARAM_LOB);
        $st->execute();
    }

    /** Beendet alle Sitzungen des Nutzers außer $keepTokenHash (Rohbytes; null: alle) und liefert ihre Anzahl. */
    public function revoke(int $uid, ?string $keepTokenHash): int
    {
        return self::revokeWith($this->db->pdo(), $uid, $keepTokenHash);
    }

    /**
     * Prüft das aktuelle Passwort nach denselben Regeln wie die Anmeldung (Fehlversuch zählt, während einer
     * Sperre wird nicht geprüft), setzt das neue und beendet alle Sitzungen außer $keepTokenHash.
     * Fehler: PASSWORD_TOO_SHORT, UNKNOWN_USER, LOCKED, BAD_CREDENTIALS.
     */
    public function changePassword(int $uid, string $current, string $next, ?string $keepTokenHash, int $now): void
    {
        Users::checkLength($next);
        $st = $this->db->pdo()->prepare('select pw_hash, locked_until from users where id = ?');
        $st->execute([$uid]);
        $row = $st->fetch();
        if ($row === false) {
            throw AuthError::of(AuthError::UNKNOWN_USER);
        }
        if ($row['locked_until'] !== null && (int) $row['locked_until'] > $now) {
            throw AuthError::of(AuthError::LOCKED);
        }
        $this->afterLockCheck();
        $hash = (string) $row['pw_hash'];
        if (!Password::verify($hash, $current)) {
            throw $this->countFailure($uid, $now);
        }
        $newHash = Password::hash($next);
        $refused = $this->db->tx(static function (PDO $pdo) use ($uid, $hash, $newHash, $now, $keepTokenHash): ?string {
            $refused = self::resetFailures($pdo, $uid, $hash, $now);
            if ($refused !== null) {
                return $refused;
            }
            $pdo->prepare('update users set pw_hash = ? where id = ?')->execute([$newHash, $uid]);
            self::revokeWith($pdo, $uid, $keepTokenHash);
            return null;
        });
        if ($refused !== null) {
            throw AuthError::of($refused);
        }
    }

    public static function randomToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Zählt einen Fehlversuch in einer Anweisung; beim zehnten wird gesperrt. Läuft die Sperre bereits ab,
     * beginnt die Zählung neu; eine aktive Sperre bleibt unberührt. Liefert den passenden Fehler.
     */
    private function countFailure(int $id, int $now): AuthError
    {
        $st = $this->db->pdo()->prepare('update users set
            failed_logins = case when locked_until is not null then 1 else failed_logins + 1 end,
            locked_until = case when (case when locked_until is not null then 1 else failed_logins + 1 end) >= :max
                then :until else null end
            where id = :id and (locked_until is null or locked_until <= :now)');
        // Als Zahlen binden: execute([...]) bindet Text, und in SQLite ist jede Zahl kleiner als Text.
        foreach (['max' => self::MAX_FAILED_LOGINS, 'until' => $now + self::LOCK_DURATION, 'id' => $id, 'now' => $now] as $k => $v) {
            $st->bindValue($k, $v, PDO::PARAM_INT);
        }
        $st->execute();
        // Keine Zeile: Sperre ist inzwischen aktiv, Antwort wie bei richtigem Passwort.
        return AuthError::of($st->rowCount() === 0 ? AuthError::LOCKED : AuthError::BAD_CREDENTIALS, $id);
    }

    /**
     * In der Schreibtransaktion: Ist inzwischen eine Sperre aktiv, LOCKED. Ist das Konto gesperrt oder hat sich
     * der Hash seit der Prüfung geändert (Reset oder Passwortwechsel dazwischen), BAD_CREDENTIALS wie bei falschem
     * Passwort, damit nichts mit dem alten Passwort gelingt. Sonst wird der Fehlerzähler zurückgesetzt (null).
     * Liefert den Grund statt zu werfen: Der Aufrufer wirft ihn erst nach der Transaktion, die normal endet (vor
     * dem Grund ist nichts geschrieben). Database::tx rollte bei einer Exception ebenso sauber zurück.
     */
    private static function resetFailures(PDO $pdo, int $id, string $checkedHash, int $now): ?string
    {
        $st = $pdo->prepare('select pw_hash, locked_until, disabled_at from users where id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        if ($row === false) {
            return AuthError::BAD_CREDENTIALS;
        }
        if ($row['locked_until'] !== null && (int) $row['locked_until'] > $now) {
            return AuthError::LOCKED;
        }
        if ($row['disabled_at'] !== null || !hash_equals((string) $row['pw_hash'], $checkedHash)) {
            return AuthError::BAD_CREDENTIALS;
        }
        $pdo->prepare('update users set failed_logins = 0, locked_until = null where id = ?')->execute([$id]);
        return null;
    }

    private static function revokeWith(PDO $pdo, int $uid, ?string $keepTokenHash): int
    {
        if ($keepTokenHash === null) {
            $st = $pdo->prepare('delete from web_sessions where user_id = ?');
            $st->bindValue(1, $uid, PDO::PARAM_INT);
        } else {
            $st = $pdo->prepare('delete from web_sessions where user_id = ? and token_hash <> ?');
            $st->bindValue(1, $uid, PDO::PARAM_INT);
            $st->bindValue(2, $keepTokenHash, PDO::PARAM_LOB);
        }
        $st->execute();
        return $st->rowCount();
    }

    private function afterLockCheck(): void
    {
        if ($this->afterLockCheck !== null) {
            ($this->afterLockCheck)();
        }
    }

    /**
     * Fester Hash für unbekannte Nutzer mit denselben Parametern wie Password::hash, fest eingetragen,
     * weil jede PHP-Anfrage neu beginnt und ein frisch berechneter Hash den Aufwand verdoppeln würde.
     */
    private static function dummyHash(): string
    {
        return PASSWORD_ARGON2_PROVIDER === 'standard'
            ? '$argon2id$v=19$m=65536,t=3,p=2$ZUJvcWp3MHBlMi53TjRhWQ$wjziZWCjalNhIvW+2R1Ix1LynwIm3JwJUHikZGhMJF0'
            : '$argon2id$v=19$m=65536,t=3,p=1$Wjg3bGlwSjNZd1pvWGJHZg$3aBup+n63UO1M0o/aSlljN4FQBGuugkfGmNIyYnmOKo';
    }
}
