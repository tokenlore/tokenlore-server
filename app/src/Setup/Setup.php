<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

use Closure;
use RuntimeException;
use Tokenlore\Auth\Users;
use Tokenlore\Config\Paths;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Db\Database;
use Tokenlore\Db\Migrator;
use Tokenlore\Http\Request;
use Tokenlore\RateLimit\Network;

// Die Einrichtung im Browser: wann sie nötig ist, was sie anlegt und die Prüfungen per Selbstabruf.
// Die Seite dazu steht in Handlers\SetupHandlers. Es gibt keine Anmeldung und keine Ratengrenze (beides
// braucht die Datenbank, die es noch nicht gibt); die Einrichtung ist nur offen, solange kein Konto existiert,
// und verlangt eine Nachweisdatei im Datenordner (PROOF_FILE), die nur der Besitzer per FTP ablegen kann.
final class Setup
{
    /** Fehlertext der API (503) vor der Einrichtung; rewriteWorks() erkennt daran, dass die Anwendung antwortet. */
    public const NOT_READY = 'Einrichtung nicht abgeschlossen';

    // Ergebnisse von dataFolderExposure().
    public const EXPOSED = 'exposed';
    public const SAFE = 'protected';
    public const UNKNOWN = 'unknown';
    public const OUTSIDE = 'outside';

    /** Header des Selbstabrufs auf healthz: kein Geheimnis, nur ein Zeichen, ob der Header bei PHP ankommt. */
    public const PROBE_AUTHORIZATION = 'Bearer tl_probe';

    /**
     * Nachweis, dass der Besucher den Server besitzt: Diese Datei im Datenordner muss den Code der Seite enthalten
     * (proofCode). Sonst richtete jeder, der die frische Adresse zuerst findet, das Admin-Konto ein.
     */
    public const PROOF_FILE = 'setup-code.txt';
    /** So lange gilt eine hochgeladene Nachweisdatei. */
    public const PROOF_TTL = 86400;

    private const SQLITE_MAGIC = "SQLite format 3\0";
    private const LOCK_FILE = 'setup.lock';

    /** @var Closure(string, array<string,string>=): ?array{status:int, head:string} */
    private readonly Closure $fetch;

    /** @var array<string, array{status:int, head:string}|null> Antworten von healthz je Adresse */
    private array $healthAnswers = [];

    /** @var array<string, string> Ergebnisse von dataFolderExposure je Adresse (run() verwirft sie) */
    private array $exposureAnswers = [];

    /**
     * @param (callable(string): ?array{status:int, head:string})|null $fetch Abrufer für die Selbstprüfungen
     *        (SetupHandlers gibt SelfFetch::forRequest); ohne Abrufer ist jede Prüfung „unklar“
     */
    public function __construct(private readonly Paths $paths, ?callable $fetch = null)
    {
        $this->fetch = $fetch === null ? static fn(string $url): ?array => null : Closure::fromCallable($fetch);
    }

    /**
     * true, solange es keine Datenbank oder kein Konto gibt. Legt nichts an. Wirft, wenn im Datenordner
     * mehr als eine Datenbank liegt (Paths::databaseFile); dann bleibt die Einrichtung zu.
     */
    public static function needed(Paths $paths): bool
    {
        $file = $paths->databaseFile();
        if ($file === null) {
            return true;
        }
        $db = Database::open($file);
        try {
            $pdo = $db->pdo();
            $table = $pdo->query("select 1 from sqlite_master where type = 'table' and name = 'users'")->fetchColumn();
            if ($table === false) {
                return true; // Datei ohne Tabellen, etwa von einem abgebrochenen Versuch
            }
            return $pdo->query('select 1 from users limit 1')->fetchColumn() === false;
        } finally {
            $db->close();
        }
    }

    /**
     * Legt die Datenbank mit neuem Zufallsnamen an (eine Datenbank aus einem abgebrochenen Versuch wird dafür
     * umbenannt), stellt sie auf den neuesten
     * Stand, speichert Proxy-Schalter und öffentliche Adresse und erstellt zuletzt das Admin-Konto (das ist die
     * Sperre: ab dann ist needed() false). Eine ungültige $publicUrl (etwa http) wird nicht gespeichert, die
     * Adresse wird dann bei jeder Anfrage erkannt. Alles läuft unter einer Dateisperre, zwei gleichzeitige
     * Aufrufe richten also nie zwei Konten ein.
     *
     * @throws SetupClosed wenn schon ein Konto existiert
     * @throws \Tokenlore\Auth\AuthError bei ungültigem Namen oder Passwort (die Einrichtung bleibt dann offen)
     */
    public function run(string $username, string $pw, ?string $publicUrl = null, bool $trustProxy = false): void
    {
        $lockPath = $this->paths->dataDir() . '/' . self::LOCK_FILE;
        $lock = @fopen($lockPath, 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('Sperrdatei im Datenordner nicht nutzbar.');
        }
        // Nach dem Abschluss prüft die Bestätigung den Datenordner frisch.
        $this->exposureAnswers = [];
        try {
            if (!self::needed($this->paths)) {
                throw new SetupClosed();
            }
            $db = Database::open($this->freshDatabaseFile());
            try {
                (new Migrator($db, $this->paths))->migrate();
                $changes = ['trust_proxy' => $trustProxy];
                if ($publicUrl !== null && ServerSettings::validPublicUrl($publicUrl)) {
                    $changes['public_url'] = $publicUrl;
                }
                ServerSettings::load($db)->save($changes);
                (new Users($db))->create($username, $pw, 'admin');
            } finally {
                $db->close();
            }
            ProofFile::remove($this->proofPath());
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Der Code, den die Nachweisdatei enthalten muss, abgeleitet aus dem Formular-Token des Besuchers (Cookie).
     * Wer die Datei liest, kann den Code nicht für ein eigenes Token verwenden.
     */
    public static function proofCode(string $token): string
    {
        return substr(hash('sha256', 'tokenlore-setup-proof:' . $token), 0, 32);
    }

    /** Liegt die Nachweisdatei mit dem Code zu $token im Datenordner (siehe ProofFile)? */
    public function proofPresent(string $token, ?int $now = null): bool
    {
        return ProofFile::matches($this->proofPath(), self::proofCode($token), $now ?? time(), self::PROOF_TTL);
    }

    private function proofPath(): string
    {
        return $this->paths->dataDir() . '/' . self::PROOF_FILE;
    }

    /**
     * Antwortet <base>/<file> mit der Datenbankdatei? true: ja (200 oder 206 mit dem Anfang einer SQLite-Datei);
     * false: nein (gesperrt, nicht gefunden, weitergeleitet oder eine andere Seite statt der Datei, etwa die
     * Sammelantwort eines Servers); null: unklar (kein Abruf möglich, Serverfehler).
     *
     * @param string $file Pfad relativ zur Basisadresse, z. B. data/probe-<zufall>.sqlite. Nie der Name der echten
     *        Datenbank: die Basisadresse stammt aus dem Host-Header des Besuchers.
     */
    public function reachability(string $baseUrl, string $file): ?bool
    {
        $answer = ($this->fetch)(rtrim($baseUrl, '/') . '/' . ltrim($file, '/'));
        if ($answer === null || $answer['status'] >= 500) {
            return null;
        }
        return in_array($answer['status'], [200, 206], true) && str_starts_with($answer['head'], self::SQLITE_MAGIC);
    }

    /** true nur bei sicherem Treffer: die Datenbankdatei ist von außen abrufbar (siehe reachability). */
    public function databaseReachable(string $baseUrl, string $file): bool
    {
        return $this->reachability($baseUrl, $file) === true;
    }

    /**
     * Erreicht ein Abruf von <base>/api/healthz die Anwendung (also wirken die Umschreibregeln)? Vor der
     * Einrichtung antwortet sie dort mit 503 und NOT_READY; jede andere Antwort (404 des Webservers, eine
     * Sammelseite) heißt: nein. null: unklar (kein Abruf möglich).
     */
    public function rewriteWorks(string $baseUrl): ?bool
    {
        $answer = $this->health(rtrim($baseUrl, '/') . '/api/healthz');
        if ($answer === null) {
            return null;
        }
        return self::isAppAnswer($answer);
    }

    /**
     * Kommt der Authorization-Header (der Geräteschlüssel der Plugins) bei PHP an? Bei Apache mit CGI/FastCGI
     * geht er ohne die Regeln der .htaccess verloren. Gefragt wird die Anwendung selbst: Ihr healthz vor der
     * Einrichtung meldet, ob der mitgeschickte Header (Bearer tl_probe) ankam. Mit $rewrite === true dient die
     * Antwort aus rewriteWorks(), sonst geht der Abruf über index.php. null: unklar (kein Abruf möglich, oder die
     * Anwendung antwortete nicht).
     *
     * @param ?bool $rewrite Ergebnis von rewriteWorks() für dieselbe Adresse
     */
    public function authorizationArrives(string $baseUrl, ?bool $rewrite): ?bool
    {
        if ($rewrite === null) {
            return null;
        }
        $url = rtrim($baseUrl, '/') . ($rewrite ? '/api/healthz' : '/index.php/api/healthz');
        $answer = $this->health($url);
        if ($answer === null || !self::isAppAnswer($answer)) {
            return null;
        }
        $data = json_decode($answer['head'], true);
        return is_array($data) && is_bool($data['authorization'] ?? null) ? $data['authorization'] : null;
    }

    /**
     * Abruf von healthz mit dem Probe-Header; die Antwort je Adresse wird gemerkt (rewriteWorks und
     * authorizationArrives fragen so nur einmal).
     *
     * @return array{status:int, head:string}|null
     */
    private function health(string $url): ?array
    {
        if (!array_key_exists($url, $this->healthAnswers)) {
            $this->healthAnswers[$url] = ($this->fetch)($url, ['Authorization' => self::PROBE_AUTHORIZATION]);
        }
        return $this->healthAnswers[$url];
    }

    /** @param array{status:int, head:string} $answer */
    private static function isAppAnswer(array $answer): bool
    {
        return $answer['status'] === 503 && str_contains($answer['head'], self::NOT_READY);
    }

    /**
     * Prüft, ob der Datenordner über die Webadresse abrufbar ist, mit einer Wegwerf-Probedatei (probe-<32 Hex>.sqlite,
     * der SQLite-Anfang plus Zufall), die in jedem Fall danach gelöscht wird. Der Name der echten Datenbank geht nie
     * in einen Abruf. Liegt der Datenordner außerhalb des Installationsordners, ist er nicht über die Adresse des
     * Servers erreichbar: OUTSIDE, kein Abruf. Das Ergebnis je Adresse wird gemerkt (bis run()), damit eine Anfrage
     * höchstens eine Probedatei schreibt und abruft.
     *
     * @return self::EXPOSED|self::SAFE|self::UNKNOWN|self::OUTSIDE
     */
    public function dataFolderExposure(string $baseUrl): string
    {
        return $this->exposureAnswers[$baseUrl] ??= $this->probeDataFolder($baseUrl);
    }

    /** @return self::EXPOSED|self::SAFE|self::UNKNOWN|self::OUTSIDE */
    private function probeDataFolder(string $baseUrl): string
    {
        $urlPath = $this->dataUrlPath();
        if ($urlPath === null) {
            return self::OUTSIDE;
        }
        // Nie mit dem Namen der echten Datenbank: Die Basisadresse stammt aus dem Host-Header des Besuchers, der
        // sie sonst auf einen eigenen Host lenken und den geheimen Dateinamen erfahren könnte.
        $name = 'probe-' . bin2hex(random_bytes(16)) . '.sqlite';
        $probe = $this->paths->dataDir() . '/' . $name;
        try {
            if (file_put_contents($probe, self::SQLITE_MAGIC . random_bytes(48)) === false) {
                return self::UNKNOWN;
            }
            return self::label($this->reachability($baseUrl, $urlPath . '/' . $name));
        } catch (\Throwable) {
            return self::UNKNOWN;
        } finally {
            if (is_file($probe)) {
                @unlink($probe);
            }
        }
    }

    /**
     * Pfad für die Datenbank dieser Einrichtung: immer ein neuer Zufallsname. Eine Datenbank aus einem
     * abgebrochenen Versuch (ohne Konto) wird dafür umbenannt, samt WAL- und SHM-Datei; so bleibt kein Name
     * erhalten, der schon einmal irgendwo gestanden haben könnte.
     */
    private function freshDatabaseFile(): string
    {
        $fresh = $this->paths->newDatabaseFile();
        $orphan = $this->paths->databaseFile();
        if ($orphan !== null) {
            foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
                if (is_file($orphan . $suffix) && !rename($orphan . $suffix, $fresh . $suffix)) {
                    throw new RuntimeException('Datenbank aus einem abgebrochenen Versuch lässt sich nicht umbenennen.');
                }
            }
        }
        return $fresh;
    }

    /**
     * Pfad des Datenordners unterhalb der Basisadresse (Standard „data“), je Segment kodiert; null, wenn der
     * Ordner nicht im Installationsordner liegt.
     */
    public function dataUrlPath(): ?string
    {
        $install = rtrim(str_replace('\\', '/', $this->paths->installDir()), '/') . '/';
        $data = str_replace('\\', '/', $this->paths->dataDir());
        if (!str_starts_with($data . '/', $install) || $data . '/' === $install) {
            return null;
        }
        $segments = explode('/', trim(substr($data, strlen($install)), '/'));
        if (in_array('..', $segments, true) || in_array('.', $segments, true) || in_array('', $segments, true)) {
            return null;
        }
        return implode('/', array_map('rawurlencode', $segments));
    }

    /**
     * Schlägt der Besucher einen Proxy vor? Ja, wenn die Anfrage X-Forwarded-For trägt und von einer
     * lokalen oder privaten Adresse kommt: typisch nginx vor Apache (Plesk). Ein Fremder von außen
     * zählt nicht, auch wenn er den Header selbst setzt.
     */
    public static function proxySuggested(Request $r): bool
    {
        $forwarded = trim($r->header('x-forwarded-for') ?? '');
        $remote = trim($r->remoteAddr);
        if ($forwarded === '' || filter_var(explode('%', $remote, 2)[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }
        return !Network::isPublicAddress($remote);
    }

    private static function label(?bool $reachable): string
    {
        return $reachable === null ? self::UNKNOWN : ($reachable ? self::EXPOSED : self::SAFE);
    }
}
