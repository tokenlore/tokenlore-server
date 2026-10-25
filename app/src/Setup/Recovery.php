<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

use Closure;
use PDO;
use Tokenlore\Auth\AuthError;
use Tokenlore\Auth\Password;
use Tokenlore\Auth\Users;
use Tokenlore\Config\Paths;
use Tokenlore\Db\Database;

// Notfall-Zugang, wenn kein Admin mehr hinein kommt. start() gibt einen Einmal-Code aus (in der Datenbank
// steht nur sha256(code)). Wer Dateien im Datenordner ablegen kann (FTP), legt den Code als reset-admin.txt
// dorthin; erst dann setzt finish() das Passwort eines Kontos, macht es zum Admin und entsperrt es.
//
// Der Besitz des Datenordners ist der eigentliche Nachweis, der Code bindet die Datei an genau diesen Vorgang:
// Eine liegengebliebene Datei nützt einem Fremden nichts, weil er den Code nicht kennt, und einen selbst
// geholten Code kann er nicht in den Datenordner legen. Code und Datei gelten höchstens TTL Sekunden.
final class Recovery
{
    public const FILE = 'reset-admin.txt';
    public const TTL = 3600;
    /** So viele gültige Codes höchstens (Schutz der Tabelle). */
    public const MAX_CODES = 1000;
    /**
     * Erst ein Code, der älter als so viele Sekunden ist, darf einem neuen weichen, wenn MAX_CODES erreicht sind.
     * Sonst verdrängte eine Flut von start-Aufrufen (verteilt auf viele IPs) den Code des Berechtigten; jetzt
     * bekommt sie 429 (RecoveryBusy), und der frische Code bleibt gültig.
     */
    public const MIN_AGE = 600;
    /** 24 Zufallsbytes base64url: 32 Zeichen. */
    private const CODE_PATTERN = '/^[A-Za-z0-9_-]{32}\z/';

    private readonly Closure $clock;

    /** @param (callable(): int)|null $clock Unix-Sekunden (Standard: time()) */
    public function __construct(private readonly Database $db, private readonly Paths $paths, ?callable $clock = null)
    {
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
    }

    /**
     * Gibt einen neuen Code aus. Ältere Codes bleiben gültig: ein Fremder, der start aufruft, macht den Code
     * des Berechtigten nicht ungültig. Sind schon MAX_CODES gültige Codes da, weicht der älteste einem neuen nur,
     * wenn er älter als MIN_AGE Sekunden ist; sonst RecoveryBusy (nichts wird gelöscht oder angelegt).
     *
     * @return array{code:string,expires_at:int}
     */
    public function start(): array
    {
        $now = ($this->clock)();
        $code = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
        $expires = $now + self::TTL;
        $retry = $this->db->tx(static function (PDO $pdo) use ($code, $expires, $now): ?int {
            $del = $pdo->prepare('delete from recovery_codes where expires_at <= ?');
            $del->bindValue(1, $now, PDO::PARAM_INT);
            $del->execute();

            $count = (int) $pdo->query('select count(*) from recovery_codes')->fetchColumn();
            if ($count >= self::MAX_CODES) {
                // Ein Code entstand bei expires_at - TTL; "älter als MIN_AGE" heißt also expires_at < now - MIN_AGE + TTL.
                $oldEnough = $now - self::MIN_AGE + self::TTL;
                $need = $count - self::MAX_CODES + 1;
                $st = $pdo->prepare('select count(*) from recovery_codes where expires_at < ?');
                $st->bindValue(1, $oldEnough, PDO::PARAM_INT);
                $st->execute();
                if ((int) $st->fetchColumn() < $need) {
                    // Voll mit frischen Codes: nichts verdrängen. Der älteste wird in (Alter bis MIN_AGE + 1) frei.
                    $oldest = (int) $pdo->query('select min(expires_at) from recovery_codes')->fetchColumn();
                    return max(1, $oldest - self::TTL + self::MIN_AGE + 1 - $now);
                }
                $evict = $pdo->prepare(
                    'delete from recovery_codes where code_hash in'
                    . ' (select code_hash from recovery_codes where expires_at < :old order by expires_at, code_hash limit :n)',
                );
                $evict->bindValue(':old', $oldEnough, PDO::PARAM_INT);
                $evict->bindValue(':n', $need, PDO::PARAM_INT);
                $evict->execute();
            }

            $ins = $pdo->prepare('insert into recovery_codes (code_hash, expires_at) values (?, ?)');
            $ins->bindValue(1, self::hash($code), PDO::PARAM_LOB);
            $ins->bindValue(2, $expires, PDO::PARAM_INT);
            $ins->execute();
            return null;
        });
        if ($retry !== null) {
            throw new RecoveryBusy($retry);
        }
        $this->removeIfStale($now);
        return ['code' => $code, 'expires_at' => $expires];
    }

    /**
     * Schließt den Vorgang ab: setzt das Passwort von $username, macht das Konto zum Admin, entsperrt es (auch
     * die Sperre nach Fehlversuchen), beendet alle seine Sitzungen und löscht alle Codes und die Datei.
     * Fehler: AuthError PASSWORD_TOO_SHORT (zuerst, verrät nichts), RecoveryDenied, AuthError UNKNOWN_USER (erst
     * nach bestandener Prüfung von Datei und Code, sonst wäre es ein Orakel für Benutzernamen).
     * Ein falscher Code ändert nichts: weder der gespeicherte Code noch die Datei werden verbraucht.
     *
     * @return int ID des Kontos (für das Sicherheitsprotokoll)
     */
    public function finish(string $code, string $username, string $password): int
    {
        Users::checkLength($password);
        $now = ($this->clock)();
        if (preg_match(self::CODE_PATTERN, $code) !== 1 || !$this->fileMatches($code, $now) || !$this->codeValid($code, $now)) {
            throw new RecoveryDenied();
        }
        $st = $this->db->pdo()->prepare('select id from users where username = ?');
        $st->execute([$username]);
        $id = $st->fetchColumn();
        if ($id === false) {
            throw AuthError::of(AuthError::UNKNOWN_USER);
        }
        $id = (int) $id;
        $hash = Password::hash($password);
        // In der Schreibtransaktion erneut prüfen: zwei gleichzeitige Abschlüsse mit demselben Code gelingen
        // nur einmal. Geschrieben wird erst nach allen Prüfungen; der Fehler fällt nach der Transaktion (die
        // dann nichts geschrieben hat; Database::tx rollte bei einer Exception ebenso zurück).
        $result = $this->db->tx(static function (PDO $pdo) use ($code, $id, $hash, $now): string {
            if (!self::codeExists($pdo, $code, $now)) {
                return 'denied';
            }
            $st = $pdo->prepare("update users set pw_hash = ?, role = 'admin', disabled_at = null, failed_logins = 0, locked_until = null where id = ?");
            $st->execute([$hash, $id]);
            if ($st->rowCount() === 0) {
                return 'unknown';
            }
            $pdo->prepare('delete from web_sessions where user_id = ?')->execute([$id]);
            $pdo->exec('delete from recovery_codes');
            return 'ok';
        });
        if ($result === 'denied') {
            throw new RecoveryDenied();
        }
        if ($result === 'unknown') {
            throw AuthError::of(AuthError::UNKNOWN_USER);
        }
        // Scheitert das Löschen, ist die Datei trotzdem wertlos: ihr Code steht nicht mehr in der Datenbank.
        $this->removeFile();
        return $id;
    }

    private static function hash(string $code): string
    {
        return hash('sha256', $code, true);
    }

    private function path(): string
    {
        return $this->paths->dataDir() . '/' . self::FILE;
    }

    private function codeValid(string $code, int $now): bool
    {
        return self::codeExists($this->db->pdo(), $code, $now);
    }

    /** Gibt es den Code (nur sein Hash steht in der Tabelle) und gilt er zum Zeitpunkt $now noch? */
    private static function codeExists(PDO $pdo, string $code, int $now): bool
    {
        $st = $pdo->prepare('select 1 from recovery_codes where code_hash = ? and expires_at > ?');
        $st->bindValue(1, self::hash($code), PDO::PARAM_LOB);
        $st->bindValue(2, $now, PDO::PARAM_INT);
        $st->execute();
        $found = $st->fetchColumn() !== false;
        $st->closeCursor();
        return $found;
    }

    /** Die Datei enthält genau den Code und ist jünger als TTL (siehe ProofFile); eine zu alte Datei wird gelöscht. */
    private function fileMatches(string $code, int $now): bool
    {
        if (ProofFile::matches($this->path(), $code, $now, self::TTL)) {
            return true;
        }
        $this->removeIfStale($now);
        return false;
    }

    /** Löscht eine liegengebliebene Datei, die älter als TTL ist. */
    private function removeIfStale(int $now): void
    {
        if (ProofFile::stale($this->path(), $now, self::TTL)) {
            $this->removeFile();
        }
    }

    /** Löscht die Datei, wenn sie ein reguläres File ist; ein Symlink oder sein Ziel bleiben unberührt. */
    private function removeFile(): void
    {
        ProofFile::remove($this->path());
    }
}
