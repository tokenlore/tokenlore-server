<?php

declare(strict_types=1);

namespace Tokenlore\Db;

use LogicException;
use PDO;
use Throwable;

// Eine SQLite-Verbindung mit den Einstellungen des Servers: WAL, Wartezeit bei belegter Datenbank
// statt sofortigem Fehler, Fremdschlüssel an, Fehler als Exceptions.
final class Database
{
    private ?PDO $pdo;

    // true, solange tx() läuft.
    private bool $inTx = false;

    private function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public static function open(string $file): self
    {
        $isNew = !file_exists($file);
        if ($isNew) {
            // Neue Datei gleich mit 0600 anlegen, nicht erst nachträglich (keine Lücke mit offenen Rechten).
            $oldUmask = umask(0077);
            try {
                touch($file);
            } finally {
                umask($oldUmask);
            }
            self::restrictToOwner($file);
        } else {
            self::tightenExisting($file);
        }
        $pdo = new PDO('sqlite:' . $file, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        // busy_timeout zuerst: schon das Umschalten auf WAL braucht eine Sperre.
        $pdo->exec('PRAGMA busy_timeout = 5000');
        $pdo->exec('PRAGMA journal_mode = WAL');
        // FULL statt NORMAL: bestätigte Daten sollen auch bei Stromausfall nicht verloren gehen.
        $pdo->exec('PRAGMA synchronous = FULL');
        $pdo->exec('PRAGMA foreign_keys = ON');
        // WAL- und SHM-Datei entstehen erst beim ersten Zugriff; SQLite legt sie mit den Rechten der
        // Datenbankdatei an, also ebenfalls 0600 (MigratorTest::testBackupAndDatabaseAreOwnerOnly).
        return new self($pdo);
    }

    // Datei nur für den Besitzer lesbar machen (0600). Unter Windows gibt es das nicht; dort bleibt
    // ein Fehlschlag folgenlos, sonst ist er einer.
    public static function restrictToOwner(string $file): void
    {
        if (!@chmod($file, 0600) && PHP_OS_FAMILY !== 'Windows') {
            throw new \RuntimeException('Dateirechte (0600) lassen sich nicht setzen: ' . $file);
        }
    }

    /**
     * Eine bestehende Datei (auch WAL und SHM, falls da), deren Rechte weiter sind als 0600 (etwa vom FTP-Programm
     * oder einer älteren Fassung angelegt), auf 0600 bringen; engere (0400) bleiben. Unter Windows entfällt das.
     * Gehört die Datei einem anderen Benutzer, scheitert chmod: das ist hier kein Grund, den Server lahmzulegen
     * (die Datenbank läuft ja), es kommt nur ins Fehlerprotokoll.
     */
    private static function tightenExisting(string $file): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return;
        }
        foreach ([$file, $file . '-wal', $file . '-shm'] as $path) {
            clearstatcache(true, $path);
            $perms = @fileperms($path);
            if ($perms === false || ($perms & 0177) === 0) {
                continue;
            }
            try {
                self::restrictToOwner($path);
            } catch (\RuntimeException $e) {
                error_log($e->getMessage());
            }
        }
    }

    public function pdo(): PDO
    {
        return $this->pdo ?? throw new LogicException('Die Datenbankverbindung ist geschlossen.');
    }

    // Schließt die Verbindung (gibt die Datei frei, wichtig unter Windows vor dem Löschen).
    public function close(): void
    {
        $this->pdo = null;
    }

    /**
     * Führt $fn in einer Transaktion aus: Rückgabewert bei Erfolg, Rollback und erneutes Werfen bei
     * einer Exception. $fn bekommt die PDO-Verbindung. Standard ist BEGIN IMMEDIATE (Schreibsperre
     * gleich zu Beginn, mit Wartezeit); mit $immediate = false ein reiner Lesevorgang (BEGIN).
     * Verschachtelung ist nicht erlaubt.
     *
     * Achtung: Fängt $fn selbst einen SQLite-Fehler ab, der die Transaktion schon abgebrochen hat (etwa
     * SQLITE_FULL oder SQLITE_IOERR), laufen alle weiteren Anweisungen von $fn im Autocommit, also
     * einzeln und nicht mehr atomar; das abschließende COMMIT scheitert dann. SQL-Fehler deshalb in $fn
     * nicht abfangen, sondern durchreichen.
     */
    public function tx(callable $fn, bool $immediate = true): mixed
    {
        $pdo = $this->pdo();
        // PDO::inTransaction() kennt vor PHP 8.4 nur Transaktionen aus PDO::beginTransaction(), keine per
        // exec('BEGIN …') gestarteten; deshalb der eigene Merker.
        if ($this->inTransaction()) {
            throw new LogicException('Transaktionen lassen sich nicht verschachteln.');
        }
        $pdo->exec($immediate ? 'BEGIN IMMEDIATE' : 'BEGIN');
        $this->inTx = true;
        try {
            $result = $fn($pdo);
            $pdo->exec('COMMIT');
            return $result;
        } catch (Throwable $e) {
            self::rollbackQuietly($pdo);
            throw $e;
        } finally {
            $this->inTx = false;
        }
    }

    // true, solange tx() läuft oder eine Transaktion per PDO::beginTransaction() offen ist.
    public function inTransaction(): bool
    {
        return $this->inTx || $this->pdo()->inTransaction();
    }

    /**
     * Rollback nach einem Fehler, ohne selbst zu werfen: Die ursprüngliche Exception ist die wichtigere.
     * Ob noch eine Transaktion offen ist, verrät PDO vor 8.4 nicht (und SQLite bricht sie bei manchen
     * Fehlern schon selbst ab); deshalb immer versuchen, „keine Transaktion aktiv“ ist dann kein Fehler.
     */
    public static function rollbackQuietly(PDO $pdo): void
    {
        try {
            $pdo->exec('ROLLBACK');
        } catch (Throwable) {
            // siehe oben
        }
    }
}
