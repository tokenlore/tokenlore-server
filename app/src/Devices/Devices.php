<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

use InvalidArgumentException;
use PDO;
use Tokenlore\Db\Database;
use Tokenlore\Util\Names;
use Tokenlore\Util\Time;

// Geräte eines Nutzers: auflisten, sperren, umbenennen (devices/keys.go, rename.go, handlers/stats.DeviceTotals).
final class Devices
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Hash eines Geräteschlüssels, wie er in device_keys.key_hash steht (SHA-256, roh). Die Datenannahme
     * prüft einen Schlüssel mit demselben Hash gegen device_keys (nicht gesperrt) und devices (nicht gesperrt).
     */
    public static function hashKey(string $key): string
    {
        return hash('sha256', $key, true);
    }

    /**
     * Die Geräte des Nutzers samt Summen über alle Anfragen, nach id. Zeiten als RFC 3339 in UTC.
     * tokens = Eingabe + Ausgabe + Cache-Aufbau + Cache-Lesen.
     *
     * @return list<array<string,mixed>>
     */
    public function list(int $uid): array
    {
        $pdo = $this->db->pdo();
        $totals = $pdo->prepare(
            'select device_id, count(*) as n,
                    sum(coalesce(input, 0) + coalesce(output, 0) + coalesce(cache_create, 0) + coalesce(cache_read, 0)) as tokens,
                    min(ts) as first_ts, max(ts) as last_ts
               from requests where user_id = ? group by device_id'
        );
        $totals->execute([$uid]);
        $byDevice = [];
        foreach ($totals as $t) {
            $byDevice[(int) $t['device_id']] = $t;
        }
        $devices = $pdo->prepare(
            'select id, name, os, arch, tz, plugin_version, last_seen_at, created_at, revoked_at is not null as revoked
               from devices where user_id = ? order by id'
        );
        $devices->execute([$uid]);
        $out = [];
        foreach ($devices as $d) {
            $t = $byDevice[(int) $d['id']] ?? null;
            $out[] = [
                'id' => (int) $d['id'],
                'name' => $d['name'],
                'os' => $d['os'],
                'arch' => $d['arch'],
                'tz' => $d['tz'],
                'plugin_version' => $d['plugin_version'],
                'last_seen_at' => $d['last_seen_at'] === null ? null : Time::isoMs((int) $d['last_seen_at'] * 1000),
                'created_at' => Time::isoMs((int) $d['created_at'] * 1000),
                'requests' => $t === null ? 0 : (int) $t['n'],
                'tokens' => $t === null ? 0 : (int) $t['tokens'],
                'first_activity' => $t === null ? null : Time::isoMs((int) $t['first_ts']),
                'last_activity' => $t === null ? null : Time::isoMs((int) $t['last_ts']),
                'revoked' => (int) $d['revoked'] === 1,
            ];
        }
        return $out;
    }

    /**
     * Sperrt ein Gerät des Nutzers samt Schlüsseln; wiederholtes Sperren ist harmlos (der erste Zeitpunkt
     * bleibt). false: unbekanntes oder fremdes Gerät.
     */
    public function revoke(int $uid, int $deviceId, int $now): bool
    {
        return (bool) $this->db->tx(static function (PDO $pdo) use ($uid, $deviceId, $now): bool {
            $dev = $pdo->prepare('update devices set revoked_at = coalesce(revoked_at, ?) where id = ? and user_id = ?');
            $dev->execute([$now, $deviceId, $uid]);
            if ($dev->rowCount() === 0) {
                return false;
            }
            $pdo->prepare('update device_keys set revoked_at = coalesce(revoked_at, ?) where device_id = ?')->execute([$now, $deviceId]);
            return true;
        });
    }

    /**
     * Benennt ein Gerät des Nutzers um (auch ein gesperrtes); der Name wird mit Names::clean bereinigt.
     * false: unbekanntes oder fremdes Gerät.
     *
     * @throws InvalidArgumentException bei unzulässigem Namen
     */
    public function rename(int $uid, int $deviceId, string $name): bool
    {
        $clean = Names::clean($name) ?? throw new InvalidArgumentException('Gerätename ungültig');
        $st = $this->db->pdo()->prepare('update devices set name = ? where id = ? and user_id = ?');
        $st->execute([$clean, $deviceId, $uid]);
        return $st->rowCount() > 0;
    }
}
