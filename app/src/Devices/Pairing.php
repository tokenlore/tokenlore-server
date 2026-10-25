<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

use Closure;
use PDO;
use PDOStatement;
use RuntimeException;
use Tokenlore\Db\Database;

// Kopplung per Kurzcode (devices/pairing.go). BEGIN IMMEDIATE ersetzt den globalen Advisory-Lock:
// Erzeugen und Einlösen laufen nacheinander, Fehlversuche zählen global.
// Zeiten sind Unix-Sekunden. Codes und Geräteschlüssel liegen nur als SHA-256 (roh, 32 Byte) in der Datenbank.
final class Pairing
{
    /** Gültigkeit eines Codes in Sekunden. */
    public const CODE_TTL = 600;
    /** Fehlversuche, nach denen ein Code ungültig ist. */
    public const MAX_FAILURES = 5;
    /** Benutzte und abgelaufene Codes räumt das Erzeugen nach diesem Alter ab (Sekunden nach Ablauf). */
    private const CLEANUP_AFTER = 86400;
    private const KEY_PREFIX = 'tl_dk_';

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
     * Code wird doppelt vergeben. Räumt nebenbei lange abgelaufene Codes ab.
     *
     * @return array{code:string, expires_at:int}
     */
    public function newCode(int $uid, int $now): array
    {
        return $this->db->tx(function (PDO $pdo) use ($uid, $now): array {
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
                $ins = $pdo->prepare('insert into pair_codes (code_hash, user_id, expires_at) values (?, ?, ?)');
                self::bindHash($ins, $hash, $uid, $expires)->execute();
                return ['code' => $code, 'expires_at' => $expires];
            }
            throw new RuntimeException('kein freier Code gefunden');
        });
    }

    /**
     * Löst einen Code ein und legt Gerät und Schlüssel an. Suchen und Verbrauchen laufen in einer
     * Transaktion mit Schreibsperre, bei Parallelität gewinnt genau ein Aufruf. project_salt ist das Salz
     * des Nutzers als Hex. Ein Fehlversuch zählt bei allen aktiven Codes mit und bleibt gespeichert.
     *
     * @return array{device_id:int, key:string, project_salt:string, user_id:int}
     * @throws BadCodeException
     */
    public function redeem(string $code, string $name, string $os, string $arch, int $now): array
    {
        $result = $this->db->tx(function (PDO $pdo) use ($code, $name, $os, $arch, $now): ?array {
            // Codes gesperrter Konten (users.disabled_at) gelten nicht; sie zählen wie ein falscher Code.
            $find = $pdo->prepare(
                'select c.id, c.user_id from pair_codes c join users u on u.id = c.user_id
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
            $pdo->prepare('update pair_codes set used_at = ? where id = ?')->execute([$now, $row['id']]);
            $salt = $pdo->prepare('select project_salt from users where id = ?');
            $salt->execute([$row['user_id']]);
            $pdo->prepare('insert into devices (user_id, name, os, arch, created_at) values (?, ?, ?, ?, ?)')
                ->execute([$row['user_id'], $name, $os, $arch, $now]);
            $deviceId = (int) $pdo->lastInsertId();
            $key = self::KEY_PREFIX . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            // Als BLOB binden: die Datenannahme sucht den Hash als BLOB, und TEXT ist in SQLite nie gleich BLOB.
            $st = $pdo->prepare('insert into device_keys (key_hash, device_id, created_at) values (?, ?, ?)');
            $st->bindValue(1, Devices::hashKey($key), PDO::PARAM_LOB);
            $st->bindValue(2, $deviceId, PDO::PARAM_INT);
            $st->bindValue(3, $now, PDO::PARAM_INT);
            $st->execute();
            return ['device_id' => $deviceId, 'key' => $key, 'project_salt' => bin2hex((string) $salt->fetchColumn()), 'user_id' => (int) $row['user_id']];
        });
        return $result ?? throw new BadCodeException();
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
