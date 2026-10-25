<?php

declare(strict_types=1);

namespace Tokenlore\Db;

use RuntimeException;
use Throwable;
use Tokenlore\Config\Paths;

// Spielt die nummerierten Umstellungen (app/migrations/NNNN_name.sql) in die Datenbank ein.
//
// Ablauf von migrate():
//  1. Schon auf dem neuesten Stand? Dann nichts tun (der Normalfall, ohne jede Sperre).
//  2. Sperrdatei im Datenordner (flock) nehmen: wer zuerst kommt, stellt um, die anderen warten.
//     VACUUM INTO geht nicht innerhalb einer Transaktion, deshalb hält die Sperre Sicherung
//     und Umstellung zusammen.
//  3. Stand unter der Sperre erneut lesen: wer zu spät kommt, tut nichts.
//  4. Sicherung backup-<alter Stand>-<Zeit>-<32 Hex Zufall>.sqlite (Rechte 0600) per VACUUM INTO
//     (nicht bei leerer Datenbank), erst unter einem Temp-Namen, nach Erfolg umbenannt; ohne Zeitlimit.
//  5. Alle offenen Umstellungen in EINER Transaktion (BEGIN EXCLUSIVE); der Stand wird in der
//     Transaktion noch einmal gelesen. Schlägt etwas fehl, bleibt alles wie vorher, und die gerade
//     angelegte Sicherung wird wieder gelöscht (sonst verdrängt ein ständig scheiternder Aufruf
//     die echten Sicherungen).
//  6. Nur die letzten fünf Sicherungen bleiben liegen.
//
// Ist die Datenbank NEUER als die Umstellungen im Ordner, wirft migrate() eine Exception.
//
// Für Umstellungsdateien gilt: sie laufen alle in einer Transaktion. Darin sind PRAGMA foreign_keys,
// VACUUM und eigene BEGIN/COMMIT-Anweisungen nicht erlaubt bzw. wirkungslos.
final class Migrator
{
    // Höchste Nummer in app/migrations/; MigratorTest::testLatestMatchesMigrationFiles prüft das.
    public const LATEST = 1;

    private const KEEP_BACKUPS = 5;
    private const LOCK_FILE = 'migrate.lock';
    // Name einer Sicherung, solange VACUUM INTO noch schreibt (tmp-backup-<32 Hex>.sqlite).
    private const TEMP_PREFIX = 'tmp-backup-';

    private readonly string $migrationsDir;

    public function __construct(
        private readonly Database $db,
        private readonly Paths $paths,
        ?string $migrationsDir = null,
    ) {
        $this->migrationsDir = $migrationsDir ?? dirname(__DIR__, 2) . '/migrations';
    }

    // Aktueller Stand der Datenbank; 0 für eine leere Datei.
    public function currentVersion(): int
    {
        $pdo = $this->db->pdo();
        $exists = $pdo->query("select 1 from sqlite_master where type = 'table' and name = 'schema_version'")->fetchColumn();
        if ($exists === false) {
            return 0;
        }
        return (int) $pdo->query('select max(version) from schema_version')->fetchColumn();
    }

    public function migrate(): void
    {
        $migrations = $this->migrations();
        $target = $migrations === [] ? 0 : max(array_keys($migrations));
        $current = $this->currentVersion();
        if ($current > $target) {
            // Daten dürfen nie verloren gehen: eine neuere Datenbank nicht mit altem Code weiterbenutzen.
            throw new RuntimeException(
                "Datenbank ist neuer als diese tokenlore-Version (Stand $current, bekannt bis $target) – bitte die neuere Version einspielen."
            );
        }
        if ($current === $target) {
            return;
        }

        $lock = $this->lock();
        try {
            $from = $this->currentVersion();
            if ($from >= $target) {
                return;
            }
            $backup = $from > 0 ? $this->backup($from) : null;
            try {
                $applied = $this->apply($migrations, $from);
            } catch (Throwable $e) {
                $this->discard($backup);
                throw $e;
            }
            if (!$applied) {
                $this->discard($backup);
                return;
            }
            $this->pruneBackups();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** @return array<int, string> Nummer => Dateipfad, aufsteigend nach Nummer */
    private function migrations(): array
    {
        if (!is_dir($this->migrationsDir)) {
            throw new RuntimeException('Migrationsordner fehlt: ' . $this->migrationsDir);
        }
        $found = [];
        foreach (scandir($this->migrationsDir) ?: [] as $name) {
            if (preg_match('/^(\d{4})_[a-z0-9_]+\.sql$/', $name, $m) !== 1) {
                continue;
            }
            $version = (int) $m[1];
            if (isset($found[$version])) {
                throw new RuntimeException("Zwei Umstellungen mit Nummer $version.");
            }
            $found[$version] = $this->migrationsDir . '/' . $name;
        }
        ksort($found);
        return $found;
    }

    /** @return resource */
    private function lock()
    {
        $path = $this->paths->dataDir() . '/' . self::LOCK_FILE;
        $handle = fopen($path, 'c');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            throw new RuntimeException('Sperrdatei im Datenordner nicht nutzbar: ' . $path);
        }
        return $handle;
    }

    /**
     * Sichert die Datenbank per VACUUM INTO zuerst unter einem Temp-Namen und benennt erst nach Erfolg um: Eine
     * abgebrochene Sicherung (Zeitlimit, Absturz) sieht so nie wie eine fertige aus. Reste solcher Abbrüche
     * räumt der nächste Lauf unter der Sperre weg. Das Zeitlimit von PHP fällt dafür weg (große Datenbanken).
     */
    private function backup(int $version): string
    {
        $dir = $this->paths->dataDir();
        $this->removeTempBackups($dir);
        if (function_exists('set_time_limit')) {
            @set_time_limit(0);
        }
        // Der Zufallsanteil macht den Namen unratbar, falls der Datenordner doch einmal über das Web
        // erreichbar wäre (eine Sicherung enthält alle Daten).
        $random = bin2hex(random_bytes(16));
        $path = $dir . '/backup-' . $version . '-' . gmdate('YmdHis') . '-' . $random . '.sqlite';
        $temp = $dir . '/' . self::TEMP_PREFIX . $random . '.sqlite';
        $pdo = $this->db->pdo();
        // Unter umask 0077 anlegen, damit die Sicherung nie mit offenen Rechten existiert.
        $oldUmask = umask(0077);
        try {
            $pdo->exec('VACUUM INTO ' . $pdo->quote($temp));
            Database::restrictToOwner($temp);
            if (!rename($temp, $path)) {
                throw new RuntimeException('Sicherung lässt sich nicht umbenennen: ' . $temp);
            }
        } catch (Throwable $e) {
            $this->removeTempBackups($dir);
            throw $e;
        } finally {
            umask($oldUmask);
        }
        return $path;
    }

    /** Löscht Temp-Dateien abgebrochener Sicherungen (nur unter der Sperre aufrufen). */
    private function removeTempBackups(string $dir): void
    {
        foreach (scandir($dir) ?: [] as $name) {
            if (preg_match('/^' . self::TEMP_PREFIX . '[0-9a-f]{32}\.sqlite(-journal|-wal|-shm)?$/', $name) === 1) {
                @unlink($dir . '/' . $name);
            }
        }
    }

    private function discard(?string $backup): void
    {
        if ($backup !== null && is_file($backup)) {
            unlink($backup);
        }
    }

    /**
     * @param array<int, string> $migrations
     * @return bool false, wenn inzwischen jemand anderes umgestellt hat (dann ist nichts zu tun)
     */
    private function apply(array $migrations, int $expectedFrom): bool
    {
        $pdo = $this->db->pdo();
        $pdo->exec('BEGIN EXCLUSIVE');
        try {
            // Stand unter der Datenbanksperre noch einmal lesen: wer zu spät kommt, tut nichts.
            $current = $this->currentVersion();
            if ($current !== $expectedFrom) {
                $pdo->exec('ROLLBACK');
                return false;
            }
            foreach ($migrations as $version => $file) {
                if ($version <= $current) {
                    continue;
                }
                $sql = file_get_contents($file);
                if ($sql === false) {
                    throw new RuntimeException("Umstellung nicht lesbar: $file");
                }
                $pdo->exec($sql);
                // schema_version legt 0001 selbst an; ab da führt der Migrator die Nummer nach.
                $pdo->exec('DELETE FROM schema_version');
                $pdo->exec('INSERT INTO schema_version (version) VALUES (' . $version . ')');
            }
            $pdo->exec('COMMIT');
            return true;
        } catch (Throwable $e) {
            // Nicht über $pdo->inTransaction() entscheiden: vor PHP 8.4 kennt es BEGIN EXCLUSIVE nicht.
            Database::rollbackQuietly($pdo);
            throw $e;
        }
    }

    private function pruneBackups(): void
    {
        $dir = $this->paths->dataDir();
        $backups = [];
        foreach (scandir($dir) ?: [] as $name) {
            if (preg_match('/^backup-(\d+)-(\d{14})-[0-9a-f]{32}\.sqlite$/', $name, $m) === 1) {
                $backups[$name] = sprintf('%010d-%s', (int) $m[1], $m[2]);
            }
        }
        // Neueste zuerst: höherer Stand, bei gleichem Stand die spätere Zeit.
        arsort($backups, SORT_STRING);
        foreach (array_slice(array_keys($backups), self::KEEP_BACKUPS) as $name) {
            unlink($dir . '/' . $name);
        }
    }
}
