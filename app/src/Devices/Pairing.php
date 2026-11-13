<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

use Closure;
use PDO;
use PDOStatement;
use RuntimeException;
use Tokenlore\Db\Database;
use Tokenlore\Protocol\Limits;
use Tokenlore\Util\Time;

// Kopplung per Kurzcode (devices/pairing.go). BEGIN IMMEDIATE ersetzt den globalen Advisory-Lock:
// Erzeugen und Einlösen laufen nacheinander, Fehlversuche zählen global.
// Zeiten sind Unix-Sekunden. Codes und Geräteschlüssel liegen nur als SHA-256 (roh, 32 Byte) in der Datenbank.
// Ein Rechner bleibt je Benutzer ein Gerät: Die Kennung des Rechners (device_source) steht in device_sources; Koppeln
// mit einer bekannten Kennung koppelt das Gerät neu, statt ein zweites anzulegen. Gespeichert wird die Kennung nur als
// HMAC mit dem Salz des Benutzers (storedSource), sodass derselbe Rechner unter zwei Konten nicht verknüpfbar ist.
final class Pairing
{
    /** Gültigkeit eines Codes in Sekunden. */
    public const CODE_TTL = 600;
    /** Fehlversuche, nach denen ein Code ungültig ist. */
    public const MAX_FAILURES = 5;
    /** Benutzte und abgelaufene Codes räumt das Erzeugen nach diesem Alter ab (Sekunden nach Ablauf). */
    private const CLEANUP_AFTER = 86400;
    private const KEY_PREFIX = 'tl_dk_';
    /** Liegt die letzte Lieferung des Vorgängers weniger Sekunden zurück, gilt er als in Gebrauch (recent). */
    public const PREDECESSOR_RECENT = 86400;

    private readonly Closure $genCode;

    /** @param (callable(): string)|null $genCode liefert den 6-stelligen Code (Standard: Zufall; nur für Tests ersetzbar) */
    public function __construct(private readonly Database $db, ?callable $genCode = null)
    {
        $this->genCode = $genCode === null
            ? static fn(): string => sprintf('%06d', random_int(0, 999_999))
            : Closure::fromCallable($genCode);
    }

    /**
     * Erzeugt einen 6-stelligen Code; der vorherige aktive Code des Nutzers wird ungültig und kein aktiver
     * Code wird doppelt vergeben. Räumt nebenbei lange abgelaufene Codes ab. Mit $deviceId gilt der Code für
     * dieses Gerät des Nutzers (auch ein gesperrtes) und koppelt es beim Einlösen neu.
     *
     * @return array{code:string, expires_at:int, device:array{id:int, name:string}|null}|null null: $deviceId ist
     *         kein Gerät dieses Nutzers (nichts geändert)
     */
    public function newCode(int $uid, int $now, ?int $deviceId = null): ?array
    {
        return $this->db->tx(function (PDO $pdo) use ($uid, $now, $deviceId): ?array {
            $device = null;
            if ($deviceId !== null) {
                $dev = $pdo->prepare('select id, name from devices where id = ? and user_id = ?');
                $dev->execute([$deviceId, $uid]);
                $row = $dev->fetch(PDO::FETCH_ASSOC);
                if ($row === false) {
                    return null;
                }
                $device = ['id' => (int) $row['id'], 'name' => (string) $row['name']];
            }
            $pdo->prepare('update pair_codes set used_at = ? where user_id = ? and used_at is null')->execute([$now, $uid]);
            $pdo->prepare('delete from pair_codes where expires_at < ?')->execute([$now - self::CLEANUP_AFTER]);
            $taken = $pdo->prepare(
                'select exists (select 1 from pair_codes where code_hash = ? and used_at is null and expires_at > ? and failed_attempts < ?)'
            );
            for ($try = 0; $try < 20; $try++) {
                $code = ($this->genCode)();
                $hash = self::hashCode($code);
                self::bindHash($taken, $hash, $now, self::MAX_FAILURES)->execute();
                if ((int) $taken->fetchColumn() === 1) {
                    continue;
                }
                $expires = $now + self::CODE_TTL;
                $ins = $pdo->prepare('insert into pair_codes (code_hash, user_id, expires_at, device_id) values (?, ?, ?, ?)');
                self::bindHash($ins, $hash, $uid, $expires);
                $ins->bindValue(4, $deviceId, $deviceId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
                $ins->execute();
                return ['code' => $code, 'expires_at' => $expires, 'device' => $device];
            }
            throw new RuntimeException('kein freier Code gefunden');
        });
    }

    /**
     * Löst einen Code ein. Suchen und Verbrauchen laufen in einer Transaktion mit Schreibsperre, bei Parallelität
     * gewinnt genau ein Aufruf. Ein Fehlversuch zählt bei allen aktiven Codes mit und bleibt gespeichert.
     *
     * Welches Gerät: Gilt der Code für ein Gerät, ist es dieses (eine noch unbekannte Kennung wird ihm
     * zugeordnet); sonst das Gerät des Nutzers mit dieser Kennung; sonst ein neues Gerät mit dieser Kennung.
     * Ein bestehendes Gerät wird neu gekoppelt: alle bis dahin aktiven Schlüssel gesperrt (Grund 'repaired'; schon
     * gesperrte behalten ihren Grund), eine Sperre
     * des Geräts aufgehoben, Betriebssystem und Architektur aktualisiert, Daten unverändert. Den Namen ersetzt
     * es nur bei $nameExplicit; sonst bleibt der bisherige, etwa auf der Webseite vergebene Name. Ein neues Gerät
     * bekommt immer $name. Das Salz des Nutzers (users.source_salt) verlässt den Server nie.
     *
     * Signaturschlüssel: $signKey steht am neuen Eintrag in device_keys (auch wenn das Gerät ihn schon an einem älteren
     * Eintrag hat); jeder Eintrag aus $previousSignKeys, den das Gerät noch nicht hat, kommt nach device_sign_keys.
     * Ein Schlüssel gehört genau einem Gerät über alle Benutzer. Ein mit Besitznachweis gemeldeter Schlüssel steht in
     * device_keys, ein früherer ohne Nachweis in device_sign_keys. Der aktuelle $signKey (der Handler hat seinen
     * Nachweis geprüft) kommt immer an dieses Gerät: Hat ihn ein anderes Gerät, als früheren oder mit Nachweis, nimmt
     * redeem ihn dort weg (der neueste gültige Nachweis gewinnt, Entscheidungen Z4 a und Z7 a). Einen früheren
     * Schlüssel, den ein anderes Gerät schon hat, übernimmt redeem nicht, koppelt trotzdem und nennt ihn in
     * sign_keys_refused. Hat das Gerät danach mehr als Limits::MAX_SIGN_KEYS_PER_DEVICE Schlüssel, fallen die ältesten
     * früheren weg (Devices::capSignKeys); der aktuelle bleibt immer. Jeder angenommene Nachweis (Schlüssel und Code)
     * gilt nur einmal, auch wenn newCode den Code später neu vergibt (pair_proofs, Entscheidung Z9 a).
     *
     * Vorgänger (protocol/doc.md, „Vorgänger“): Gilt der Code für kein bestimmtes Gerät, ist $source dem Nutzer unbekannt
     * und gehört $predecessorSource einem Gerät A des Nutzers (über device_sources, nach einem Zusammenlegen also dem
     * aufnehmenden Gerät), fragt redeem ohne $predecessorAnswer nach (PredecessorQuestion, nichts geändert, Code und
     * Besitznachweis bleiben unverbraucht). 'same' koppelt A neu wie ein Code für A; 'new' und 'later' legen ein neues
     * Gerät B an und merken das Paar (B, A) in device_predecessors als 'rejected' bzw. 'open'. Steht keine Frage an,
     * wird $predecessorAnswer übergangen. Ein Eintrag für das Paar kann hier nicht schon bestehen: B gibt es erst, wenn
     * $source bekannt ist, und dann fragt redeem nicht.
     *
     * @param string $source Kennung des Rechners (device_source, geprüft mit Validator::deviceSource)
     * @param bool $nameExplicit Name ausdrücklich gewählt (device_name_explicit, Plugin mit --name)
     * @param string|null $signKey aktueller Signaturschlüssel (sign_public_key), 32 Byte roh
     * @param list<string> $previousSignKeys frühere Signaturschlüssel (sign_public_keys_previous), je 32 Byte roh
     * @param string|null $pluginVersion gemeldete Plugin-Version; null lässt devices.plugin_version unverändert
     * @param string|null $predecessorSource Kennung des Vorgängers (predecessor_source, geprüft mit Validator::deviceSource)
     * @param 'same'|'new'|'later'|null $predecessorAnswer Antwort auf die Frage (predecessor_answer)
     * @return array{device_id:int, key:string, user_id:int, repaired:bool, sign_keys_refused:list<string>} abgelehnte
     *         Schlüssel roh, in der gesendeten Reihenfolge (aktueller zuerst), ohne Doppelte
     * @throws BadCodeException
     * @throws SourceTaken Code für ein Gerät, Kennung gehört einem anderen Gerät desselben Nutzers (nichts geändert)
     * @throws ProofReused derselbe Schlüssel wurde mit diesem Code schon einmal gekoppelt (nichts geändert)
     * @throws PredecessorQuestion Frage nach dem Vorgänger (nichts geändert)
     */
    public function redeem(
        string $code,
        string $name,
        string $os,
        string $arch,
        string $source,
        int $now,
        bool $nameExplicit = false,
        ?string $signKey = null,
        array $previousSignKeys = [],
        ?string $pluginVersion = null,
        ?string $predecessorSource = null,
        ?string $predecessorAnswer = null,
    ): array {
        $result = $this->db->tx(function (PDO $pdo) use ($code, $name, $os, $arch, $source, $now, $nameExplicit, $signKey, $previousSignKeys, $pluginVersion, $predecessorSource, $predecessorAnswer): ?array {
            // Codes gesperrter Konten (users.disabled_at) gelten nicht; sie zählen wie ein falscher Code.
            $find = $pdo->prepare(
                'select c.id, c.user_id, c.device_id from pair_codes c join users u on u.id = c.user_id
                  where c.code_hash = ? and c.used_at is null and c.expires_at > ? and c.failed_attempts < ?
                    and u.disabled_at is null
                  order by c.id limit 1'
            );
            self::bindHash($find, self::hashCode($code), $now, self::MAX_FAILURES)->execute();
            $row = $find->fetch();
            if ($row === false) {
                // Der Fehlversuch wird trotz Fehler gespeichert (die Transaktion endet normal).
                $pdo->prepare(
                    'update pair_codes set failed_attempts = failed_attempts + 1
                      where used_at is null and expires_at > ? and failed_attempts < ?'
                )->execute([$now, self::MAX_FAILURES]);
                return null;
            }
            $uid = (int) $row['user_id'];
            $saltSt = $pdo->prepare('select source_salt from users where id = ?');
            $saltSt->execute([$uid]);
            $salt = (string) $saltSt->fetchColumn();
            $stored = self::storedSource($source, $salt);
            $src = $pdo->prepare('select device_id from device_sources where user_id = ? and source = ?');
            $src->execute([$uid, $stored]);
            $known = $src->fetchColumn();
            $known = $known === false ? null : (int) $known;

            $deviceId = $row['device_id'] === null ? $known : (int) $row['device_id'];
            if ($row['device_id'] !== null && $known !== null && $known !== $deviceId) {
                // Die Ausnahme rollt die Transaktion zurück: Der Code bleibt gültig, nichts wird geändert.
                throw new SourceTaken($uid);
            }
            if ($signKey !== null) {
                // Ein Nachweis gilt nur einmal (Entscheidung Z9 a): Der Code allein reicht dafür nicht, weil newCode
                // einen benutzten Code neu vergeben kann. Die Ausnahme rollt zurück, der Code bleibt gültig.
                $fp = self::proofFingerprint($signKey, $code);
                $seen = $pdo->prepare('select exists (select 1 from pair_proofs where fingerprint = ?)');
                $seen->bindValue(1, $fp, PDO::PARAM_LOB);
                $seen->execute();
                if ((int) $seen->fetchColumn() === 1) {
                    throw new ProofReused($uid);
                }
                $seen->closeCursor();
            }
            // Vorgänger erst nach allen anderen Prüfungen und vor dem Merken des Nachweises: Die Frage verbraucht weder
            // Code noch Nachweis, das Plugin koppelt danach mit beiden und der Antwort erneut.
            $predecessor = null;
            if ($row['device_id'] === null && $known === null && $predecessorSource !== null) {
                $src->execute([$uid, self::storedSource($predecessorSource, $salt)]);
                $found = $src->fetchColumn();
                $predecessor = $found === false ? null : (int) $found;
            }
            $sent = $signKey === null ? $previousSignKeys : [$signKey, ...$previousSignKeys];
            if ($predecessor !== null && $predecessorAnswer === null) {
                $info = self::predecessorInfo($pdo, $predecessor, $now, $sent);
                // Die Ausnahme rollt die Transaktion zurück: Der Code bleibt gültig, nichts wird geändert.
                throw new PredecessorQuestion($uid, $info, self::recommendation($info));
            }
            if ($predecessor !== null && $predecessorAnswer === 'same') {
                $deviceId = $predecessor;
            }
            if ($signKey !== null) {
                $mark = $pdo->prepare('insert into pair_proofs (fingerprint, used_at) values (?, ?)');
                $mark->bindValue(1, $fp, PDO::PARAM_LOB);
                $mark->bindValue(2, $now, PDO::PARAM_INT);
                $mark->execute();
            }
            $pdo->prepare('update pair_codes set used_at = ? where id = ?')->execute([$now, $row['id']]);
            $repaired = $deviceId !== null;
            if ($repaired) {
                // Nur bis dahin aktive Schlüssel bekommen den Grund 'repaired'; ein schon gesperrter behält Zeit und Grund.
                $pdo->prepare(
                    "update device_keys set revoked_at = ?, revoked_reason = 'repaired' where device_id = ? and revoked_at is null"
                )->execute([$now, $deviceId]);
                // coalesce(null, name) behält den bisherigen Namen.
                $pdo->prepare('update devices set name = coalesce(?, name), os = ?, arch = ?, revoked_at = null where id = ? and user_id = ?')
                    ->execute([$nameExplicit ? $name : null, $os, $arch, $deviceId, $uid]);
            } else {
                $pdo->prepare('insert into devices (user_id, name, os, arch, created_at) values (?, ?, ?, ?, ?)')
                    ->execute([$uid, $name, $os, $arch, $now]);
                $deviceId = (int) $pdo->lastInsertId();
            }
            if ($pluginVersion !== null) {
                $pdo->prepare('update devices set plugin_version = ? where id = ?')->execute([$pluginVersion, $deviceId]);
            }
            if ($predecessor !== null && !$repaired) {
                // 'new': nie wieder fragen; 'later': die Webseite fragt (Teil der Geräteliste). sign_key_match jetzt
                // merken: Unten nimmt B den aktuellen Signaturschlüssel an sich, danach hat A ihn nicht mehr.
                $pdo->prepare('insert into device_predecessors (user_id, device_id, predecessor_id, state, created_at, sign_key_match) values (?, ?, ?, ?, ?, ?)')
                    ->execute([$uid, $deviceId, $predecessor, $predecessorAnswer === 'later' ? 'open' : 'rejected', $now,
                        self::signKeyMatch($pdo, $predecessor, $sent) ? 1 : 0]);
            }
            if ($known === null) {
                $pdo->prepare('insert into device_sources (user_id, source, device_id) values (?, ?, ?)')
                    ->execute([$uid, $stored, $deviceId]);
            }
            $key = self::KEY_PREFIX . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            // Als BLOB binden: die Datenannahme sucht den Hash als BLOB, und TEXT ist in SQLite nie gleich BLOB.
            $refused = [];
            $current = null;
            // Schlüssel, die das Gerät schon hat; sie kommen nicht doppelt nach device_sign_keys.
            $own = array_fill_keys(Devices::signKeysIn($pdo, $deviceId), true);
            if ($signKey !== null) {
                $own[$signKey] = true;
                // Der neueste gültige Nachweis gewinnt: Andere Geräte verlieren den Schlüssel, als früheren ohne
                // Nachweis (Entscheidung Z4 a) und ebenso mit Nachweis (Entscheidung Z7 a). Wiedereinspielen scheitert
                // an pair_proofs (oben), auch wenn derselbe Code neu vergeben wird.
                $take = $pdo->prepare('delete from device_sign_keys where device_id <> ? and sign_public_key = ?');
                $drop = $pdo->prepare('update device_keys set sign_public_key = null where device_id <> ? and sign_public_key = ?');
                foreach ([$take, $drop] as $st) {
                    $st->bindValue(1, $deviceId, PDO::PARAM_INT);
                    $st->bindValue(2, $signKey, PDO::PARAM_LOB);
                    $st->execute();
                }
                $current = $signKey;
            }
            $st = $pdo->prepare('insert into device_keys (key_hash, device_id, created_at, sign_public_key) values (?, ?, ?, ?)');
            $st->bindValue(1, Devices::hashKey($key), PDO::PARAM_LOB);
            $st->bindValue(2, $deviceId, PDO::PARAM_INT);
            $st->bindValue(3, $now, PDO::PARAM_INT);
            $st->bindValue(4, $current, $current === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
            $st->execute();
            $add = $pdo->prepare('insert into device_sign_keys (sign_public_key, device_id, created_at) values (?, ?, ?)');
            foreach ($previousSignKeys as $prev) {
                if (in_array($prev, $refused, true)) {
                    continue;
                }
                if (self::signKeyOwnedElsewhere($pdo, $prev, $deviceId)) {
                    $refused[] = $prev;
                    continue;
                }
                if (isset($own[$prev])) {
                    continue;
                }
                $own[$prev] = true;
                $add->bindValue(1, $prev, PDO::PARAM_LOB);
                $add->bindValue(2, $deviceId, PDO::PARAM_INT);
                $add->bindValue(3, $now, PDO::PARAM_INT);
                $add->execute();
            }
            Devices::capSignKeys($pdo, $deviceId);
            return [
                'device_id' => $deviceId,
                'key' => $key,
                'user_id' => $uid,
                'repaired' => $repaired,
                'sign_keys_refused' => $refused,
            ];
        });
        return $result ?? throw new BadCodeException();
    }

    /**
     * Wert für device_sources.source: Hex-HMAC-SHA256 der Kennung des Rechners, Schlüssel ist das Salz des Benutzers
     * (users.source_salt, roh). 64 Hex-Zeichen, klein.
     */
    public static function storedSource(string $source, string $salt): string
    {
        return hash_hmac('sha256', $source, $salt);
    }

    /**
     * Angaben zum Vorgänger A für die Frage, Feldnamen wie im Protokoll. recent: letzte Lieferung weniger als
     * PREDECESSOR_RECENT Sekunden vor $now; sign_key_match: einer der gesendeten Signaturschlüssel ist einer von A
     * (gleich ob an einem Geräteschlüssel, gesperrt oder als früherer).
     *
     * Dieselbe Rechnung für die Frage auf der Webseite (Devices::predecessorHints).
     *
     * @param list<string> $sent gesendete Signaturschlüssel, 32 Byte roh
     * @return array{device_id:int, name:string, last_seen_at:string|null, os:string, arch:string, recent:bool, sign_key_match:bool}
     */
    public static function predecessorInfo(PDO $pdo, int $deviceId, int $now, array $sent): array
    {
        $st = $pdo->prepare('select name, os, arch, last_seen_at from devices where id = ?');
        $st->execute([$deviceId]);
        $d = $st->fetch(PDO::FETCH_ASSOC);
        $st->closeCursor();
        $seen = $d['last_seen_at'] === null ? null : (int) $d['last_seen_at'];
        return [
            'device_id' => $deviceId,
            'name' => (string) $d['name'],
            'last_seen_at' => $seen === null ? null : Time::isoMs($seen * 1000),
            'os' => (string) $d['os'],
            'arch' => (string) $d['arch'],
            'recent' => $seen !== null && $now - $seen < self::PREDECESSOR_RECENT,
            'sign_key_match' => self::signKeyMatch($pdo, $deviceId, $sent),
        ];
    }

    /**
     * Empfehlung zur Frage nach dem Vorgänger: Hat A kürzlich geliefert (recent), scheint es noch in Gebrauch, also
     * 'new'; sonst 'same'. Nur die Empfehlung hängt daran, entschieden wird vom Nutzer.
     *
     * @param array{recent:bool} $info Angaben zu A (predecessorInfo)
     * @return 'same'|'new'
     */
    public static function recommendation(array $info): string
    {
        return $info['recent'] ? 'new' : 'same';
    }

    /**
     * true, wenn einer der Signaturschlüssel $sent (32 Byte roh) Gerät $deviceId gehört, gleich ob an einem
     * Geräteschlüssel, gesperrt oder als früherer.
     *
     * @param list<string> $sent
     */
    private static function signKeyMatch(PDO $pdo, int $deviceId, array $sent): bool
    {
        return $sent !== [] && array_intersect($sent, Devices::signKeysIn($pdo, $deviceId)) !== [];
    }

    /** true, wenn ein anderes Gerät als $deviceId (gleich welchen Benutzers) den Signaturschlüssel schon hat. */
    private static function signKeyOwnedElsewhere(PDO $pdo, string $signKey, int $deviceId): bool
    {
        $st = $pdo->prepare(
            'select exists (select 1 from device_keys where device_id <> ? and sign_public_key = ?)'
            . ' or exists (select 1 from device_sign_keys where device_id <> ? and sign_public_key = ?)'
        );
        self::bindKeyPair($st, $deviceId, $signKey)->execute();
        return (int) $st->fetchColumn() === 1;
    }

    /** Bindet Gerät und Signaturschlüssel (BLOB) zweimal hintereinander: Plätze 1/2 und 3/4. */
    private static function bindKeyPair(PDOStatement $st, int $deviceId, string $signKey): PDOStatement
    {
        foreach ([1, 3] as $i) {
            $st->bindValue($i, $deviceId, PDO::PARAM_INT);
            $st->bindValue($i + 1, $signKey, PDO::PARAM_LOB);
        }
        return $st;
    }

    /**
     * Fingerabdruck eines Besitznachweises für pair_proofs: SHA-256 (roh) über Signaturschlüssel (32 Byte) und Code. Der
     * Nachweis signiert Vorsatz, server_id und Code; die server_id ist je Server fest, Schlüssel und Code bestimmen ihn
     * also. Ed25519 signiert deterministisch, und libsodium nimmt nur die kanonische Form an.
     */
    private static function proofFingerprint(string $signKey, string $code): string
    {
        return hash('sha256', $signKey . $code, true);
    }

    private static function hashCode(string $code): string
    {
        return hash('sha256', $code, true);
    }

    /** Bindet den Code-Hash als BLOB (wie key_hash) an Platz 1 und die Zahlen danach als INTEGER. */
    private static function bindHash(PDOStatement $st, string $hash, int ...$ints): PDOStatement
    {
        $st->bindValue(1, $hash, PDO::PARAM_LOB);
        foreach ($ints as $i => $v) {
            $st->bindValue($i + 2, $v, PDO::PARAM_INT);
        }
        return $st;
    }
}
