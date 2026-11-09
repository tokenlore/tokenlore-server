<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

use Closure;
use Tokenlore\Config\Paths;

// Prüft, ob der Server die Voraussetzungen für tokenlore erfüllt, und erklärt Fehlendes in einfachen Worten.
// Die Texte erscheinen auf der Einrichtungsseite, die jeder Besucher sieht: keine Dateipfade, keine
// Feinversion von PHP.
//
// Zwei Arten von Ergebnis: Ohne die Punkte in CRITICAL läuft der Server nicht (die Einrichtung wird dann
// nicht angeboten); alles andere (HTTPS, Grenzwerte) ist eine Warnung, mit der die Einrichtung möglich bleibt.
final class Requirements
{
    public const PHP = 'PHP-Version';
    public const SQLITE = 'PHP-Erweiterung pdo_sqlite';
    public const JSON = 'PHP-Erweiterung json';
    public const OPENSSL = 'PHP-Erweiterung openssl';
    public const MBSTRING = 'PHP-Erweiterung mbstring';
    public const CTYPE = 'PHP-Erweiterung ctype';
    public const SODIUM = 'PHP-Erweiterung sodium';
    public const SQLITE_VERSION = 'SQLite-Version';
    public const SQLITE_JSON = 'SQLite-JSON-Funktionen';
    public const ARGON2ID = 'Passwort-Verfahren Argon2id';
    public const DATA_DIR = 'Datenordner beschreibbar';
    public const HTTPS = 'Verschlüsselte Verbindung (HTTPS)';
    public const MEMORY = 'Arbeitsspeicher (memory_limit)';
    public const TIME = 'Laufzeit (max_execution_time)';
    public const POST = 'Upload-Größe (post_max_size)';

    /** Ohne diese Punkte kann der Server nicht arbeiten. */
    public const CRITICAL = [
        self::PHP, self::SQLITE, self::JSON, self::OPENSSL, self::MBSTRING, self::CTYPE, self::SODIUM,
        self::SQLITE_VERSION, self::SQLITE_JSON, self::ARGON2ID, self::DATA_DIR,
    ];

    private const MIN_PHP = '8.2.0';
    // Untergrenze für SQLite (die Anfragen nutzen u. a. UPSERT und Fensterfunktionen); siehe docs/betrieb.md.
    private const MIN_SQLITE = '3.27.0';
    private const MIN_MEMORY = 128 * 1024 * 1024;
    private const MIN_TIME = 30;
    private const MIN_POST = 8 * 1024 * 1024;

    private function __construct()
    {
    }

    /**
     * @param bool $https die Seite wurde verschlüsselt aufgerufen
     * @param (callable(string): mixed)|null $env Prüffunktion für Tests. Schlüssel: php_version (string),
     *        ext:<name> (bool), argon2id (bool), writable (bool), ini:<name> (string|false)
     * @return list<array{name:string, ok:bool, hint:string}>
     */
    public static function check(Paths $paths, bool $https, ?callable $env = null): array
    {
        $env = $env === null ? self::realEnv($paths) : Closure::fromCallable($env);
        $out = [];

        $version = (string) $env('php_version');
        $out[] = self::row(
            self::PHP,
            version_compare($version, self::MIN_PHP, '>='),
            'PHP ' . self::shortVersion($version) . ' ist aktuell genug.',
            'PHP ' . self::shortVersion($version) . ' ist zu alt, nötig ist PHP 8.2 oder neuer. '
                . 'Beim Hoster lässt sich die PHP-Version meist im Kundenbereich umstellen (in Plesk unter „PHP-Einstellungen“).',
        );

        $extensions = [
            [self::SQLITE, 'pdo_sqlite', 'Sie speichert alle Daten in einer SQLite-Datenbank.'],
            [self::JSON, 'json', 'Sie liest und schreibt die Meldungen der Plugins.'],
            [self::OPENSSL, 'openssl', 'Sie prüft das hinterlegte Zertifikat und erzeugt Zufallswerte.'],
            [self::MBSTRING, 'mbstring', 'Sie verarbeitet Texte mit Umlauten und anderen Sonderzeichen richtig.'],
            [self::CTYPE, 'ctype', 'Sie prüft Eingaben wie Zahlen und Namen.'],
        ];
        foreach ($extensions as [$name, $ext, $why]) {
            $out[] = self::row(
                $name,
                (bool) $env('ext:' . $ext),
                'Vorhanden. ' . $why,
                'Die PHP-Erweiterung ' . $ext . ' fehlt. ' . $why . ' Beim Hoster lässt sie sich meist in den PHP-Einstellungen '
                    . 'einschalten (in Plesk: „PHP-Einstellungen“, Bereich „Erweiterungen“). Ohne sie läuft tokenlore nicht.',
            );
        }

        // Sodium gehört zu PHP, lässt sich beim Hoster aber abschalten; ohne sie prüft der Server keine Signaturen.
        $out[] = self::row(
            self::SODIUM,
            (bool) $env('ext:sodium'),
            'Vorhanden. Damit prüft tokenlore die Signaturen der Plugins.',
            'Die PHP-Erweiterung sodium fehlt. Damit prüft tokenlore die Signaturen der Plugins. So geht’s: '
                . 'im Hoster-Menü unter „PHP-Einstellungen“ die Erweiterung sodium anschalten (in Plesk im Bereich „Erweiterungen“) '
                . 'und die Seite neu laden. Ohne sie läuft tokenlore nicht.',
        );

        $sqlite = $env('sqlite_version');
        $sqlite = is_string($sqlite) ? $sqlite : '';
        $out[] = self::row(
            self::SQLITE_VERSION,
            $sqlite !== '' && version_compare($sqlite, self::MIN_SQLITE, '>='),
            'SQLite ' . self::shortVersion($sqlite) . ' ist aktuell genug.',
            ($sqlite === '' ? 'Die Version von SQLite ließ sich nicht lesen (meist fehlt pdo_sqlite). ' : 'SQLite ' . self::shortVersion($sqlite) . ' ist zu alt. ')
                . 'Nötig ist SQLite 3.27 oder neuer. SQLite gehört zu PHP: Eine neuere PHP-Version beim Hoster bringt meist auch ein neueres SQLite mit.',
        );

        $out[] = self::row(
            self::SQLITE_JSON,
            (bool) $env('sqlite_json'),
            'Vorhanden. Damit wertet die Datenbank die Meldungen der Plugins aus.',
            'Dieses SQLite kennt keine JSON-Funktionen (JSON1). Die Datenbank braucht sie für die Meldungen der Plugins. '
                . 'Eine neuere PHP-Version beim Hoster bringt sie meist mit. Ohne sie läuft tokenlore nicht.',
        );

        $out[] = self::row(
            self::ARGON2ID,
            (bool) $env('argon2id'),
            'Vorhanden. Damit werden Passwörter nach heutigem Stand der Technik gespeichert.',
            'Dieses PHP kann Passwörter nicht mit Argon2id sichern (es wurde ohne Argon2 gebaut). '
                . 'Wähl beim Hoster eine andere PHP-Version oder frag dort nach. Ohne Argon2id läuft tokenlore nicht.',
        );

        $out[] = self::row(
            self::DATA_DIR,
            (bool) $env('writable'),
            'Der Ordner für die Datenbank ist vorhanden und beschreibbar.',
            'In den Datenordner (Standard: der Ordner „data“ neben index.php) lässt sich nichts schreiben, oder er fehlt. '
                . 'Leg den Ordner an und vergib per FTP-Programm Schreibrechte (für den Besitzer, meist 755 oder 775). '
                . 'Liegt er woanders, steht der Pfad als „data_dir“ in der Datei config.local.php.',
        );

        $out[] = self::row(
            self::HTTPS,
            $https,
            'Die Seite wurde verschlüsselt aufgerufen.',
            'Die Seite wurde unverschlüsselt (http) aufgerufen. Das Passwort ginge dann im Klartext durchs Netz, und die Anmeldung '
                . 'im Browser funktioniert nur mit https. Richte beim Hoster ein Zertifikat ein (in Plesk: „Let’s Encrypt“) '
                . 'und ruf die Seite mit https:// auf. Steht der Server hinter einem Proxy, der https übernimmt, '
                . 'schalte unten die Option „Dieser Server steht hinter einem Proxy“ ein.',
        );

        $memory = self::bytes($env('ini:memory_limit'));
        $out[] = self::row(
            self::MEMORY,
            $memory !== null && $memory >= self::MIN_MEMORY,
            'Mindestens 128 MB stehen zur Verfügung.',
            'Pro Anfrage stehen weniger als 128 MB Arbeitsspeicher zur Verfügung. Das kann bei großen Mengen Daten zu Fehlern führen. '
                . 'Beim Hoster lässt sich „memory_limit“ meist in den PHP-Einstellungen anheben.',
        );

        $time = $env('ini:max_execution_time');
        $seconds = is_string($time) && ctype_digit(trim($time)) ? (int) trim($time) : null;
        $out[] = self::row(
            self::TIME,
            $seconds !== null && ($seconds === 0 || $seconds >= self::MIN_TIME),
            'Eine Anfrage darf mindestens 30 Sekunden dauern.',
            'Eine Anfrage darf kürzer als 30 Sekunden dauern. Große Lieferungen der Plugins könnten abgebrochen werden. '
                . 'Beim Hoster lässt sich „max_execution_time“ meist in den PHP-Einstellungen anheben.',
        );

        $post = self::bytes($env('ini:post_max_size'));
        $out[] = self::row(
            self::POST,
            $post !== null && ($post === 0 || $post >= self::MIN_POST),
            'Mindestens 8 MB je Lieferung sind erlaubt.',
            'Eine Anfrage darf kleiner als 8 MB sein. Große Lieferungen der Plugins würden abgelehnt. '
                . 'Beim Hoster lässt sich „post_max_size“ meist in den PHP-Einstellungen anheben.',
        );

        return $out;
    }

    /**
     * true, wenn einer der Punkte aus CRITICAL nicht erfüllt ist. Der Server kann dann nicht eingerichtet werden.
     *
     * @param list<array{name:string, ok:bool, hint:string}> $checks
     */
    public static function blocking(array $checks): bool
    {
        foreach ($checks as $check) {
            if (!$check['ok'] && in_array($check['name'], self::CRITICAL, true)) {
                return true;
            }
        }
        return false;
    }

    /** @return array{name:string, ok:bool, hint:string} */
    private static function row(string $name, bool $ok, string $okHint, string $failHint): array
    {
        return ['name' => $name, 'ok' => $ok, 'hint' => $ok ? $okHint : $failHint];
    }

    private static function shortVersion(string $version): string
    {
        return preg_match('/^\d+\.\d+/', $version, $m) === 1 ? $m[0] : '?';
    }

    /**
     * Wert einer php.ini-Größe („128M“, „8192K“, „1G“, Bytes, „-1“ = unbegrenzt) in Bytes; null, wenn unlesbar.
     */
    private static function bytes(mixed $value): ?int
    {
        if (!is_string($value)) {
            return null;
        }
        $value = trim($value);
        if ($value === '-1') {
            return PHP_INT_MAX;
        }
        if (preg_match('/^(\d+)([KMG]?)\z/i', $value, $m) !== 1) {
            return null;
        }
        $factor = ['' => 1, 'K' => 1024, 'M' => 1024 ** 2, 'G' => 1024 ** 3][strtoupper($m[2])];
        return (int) min((float) $m[1] * $factor, (float) PHP_INT_MAX);
    }

    private static function realEnv(Paths $paths): Closure
    {
        return static function (string $what) use ($paths): mixed {
            if ($what === 'php_version') {
                return PHP_VERSION;
            }
            if ($what === 'argon2id') {
                return defined('PASSWORD_ARGON2ID') && in_array('argon2id', password_algos(), true);
            }
            if ($what === 'writable') {
                return self::dataDirWritable($paths->dataDir());
            }
            if ($what === 'sqlite_version' || $what === 'sqlite_json') {
                return self::sqliteProbe($what === 'sqlite_version' ? 'select sqlite_version()' : "select json_valid('[]')");
            }
            if (str_starts_with($what, 'ext:')) {
                return extension_loaded(substr($what, 4));
            }
            if (str_starts_with($what, 'ini:')) {
                return ini_get(substr($what, 4));
            }
            throw new \LogicException('Unbekannte Prüfung: ' . $what);
        };
    }

    /**
     * Ergebnis einer Abfrage an eine SQLite-Datenbank im Speicher: die Version als Text, bei json_valid true/false;
     * null, wenn pdo_sqlite fehlt oder die Abfrage scheitert (etwa ohne JSON1: „no such function“).
     */
    private static function sqliteProbe(string $sql): mixed
    {
        if (!extension_loaded('pdo_sqlite')) {
            return null;
        }
        try {
            $value = (new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]))->query($sql)->fetchColumn();
        } catch (\Throwable) {
            return null;
        }
        return str_starts_with($sql, 'select json_valid') ? (int) $value === 1 : (is_string($value) ? $value : null);
    }

    // Echter Schreibversuch: is_writable() sagt unter Windows und mit ACLs oft Falsches.
    private static function dataDirWritable(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }
        $file = $dir . '/.schreibtest-' . bin2hex(random_bytes(8));
        try {
            if (file_put_contents($file, 'x') === false) {
                return false;
            }
            return true;
        } catch (\Throwable) {
            return false;
        } finally {
            if (is_file($file)) {
                @unlink($file);
            }
        }
    }
}
