<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

use PDO;
use PDOStatement;
use Tokenlore\Db\Database;
use Tokenlore\Util\GoJson;

// Speichert ein geprüftes Paket in einer Transaktion (store.go, store_sql.go). Jede Anweisung trägt user_id aus dem
// Geräteschlüssel; Zahlen werden nie verkleinert, ein erneutes Senden ändert nichts.
final class Store
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Speichert das Paket (Ergebnis von Decoder::decode, geprüft mit Decoder::validate) und setzt Gerätedaten und
     * last_seen_at. Ein BEGIN IMMEDIATE je Paket; bei einem Fehler bleibt nichts davon stehen.
     * Antwort wie im Go-Server: gelieferte Anzahlen und die markierten Sitzungen des Pakets.
     *
     * @param array<string, mixed> $batch
     * @return array{requests:int, sessions:int, accounts:int, flagged_sessions:list<string>}
     * @throws DeviceRevoked wenn Gerät, Schlüssel oder Konto inzwischen gesperrt sind oder das Gerät nicht dem Nutzer gehört
     */
    public function save(int $uid, int $deviceId, array $batch, int $nowMs): array
    {
        $pdo = $this->db->pdo();
        // Eigene Transaktion statt Database::tx: das Zurückrollen hängt so nicht an PDO::inTransaction(), das ein
        // per exec gestartetes BEGIN unter PHP 8.2 nicht erkennt.
        $pdo->exec('BEGIN IMMEDIATE');
        try {
            $flagged = $this->write($pdo, $uid, $deviceId, $batch, intdiv($nowMs, 1000));
            $pdo->exec('COMMIT');
        } catch (\Throwable $e) {
            try {
                $pdo->exec('ROLLBACK');
            } catch (\Throwable) {
                // Die ursprüngliche Exception ist die wichtigere.
            }
            throw $e;
        }
        return [
            'requests' => count($batch['requests']),
            'sessions' => count($batch['sessions']),
            'accounts' => count($batch['accounts']),
            'flagged_sessions' => $flagged,
        ];
    }

    /** @param array<string, mixed> $b @return list<string> */
    private function write(PDO $pdo, int $uid, int $dev, array $b, int $now): array
    {
        $d = $b['device'];
        $st = $pdo->prepare(
            'update devices set os = ?, arch = ?, tz = ?, plugin_version = ?, last_seen_at = ?'
            . ' where id = ? and user_id = ? and revoked_at is null'
            . ' and exists (select 1 from device_keys k where k.device_id = devices.id and k.revoked_at is null)'
            . ' and exists (select 1 from users u where u.id = devices.user_id and u.disabled_at is null)',
        );
        self::run($st, [$d['os'], $d['arch'], $d['tz'], $d['plugin_version'], $now, $dev, $uid]);
        if ($st->rowCount() !== 1) {
            throw new DeviceRevoked();
        }

        $this->storeAccounts($pdo, $uid, $b['accounts'], $now);
        $this->storeSessions($pdo, $uid, $dev, $b['sessions']);
        $this->storeRequests($pdo, $uid, $dev, $b['requests']);
        $this->storeLegacy($pdo, $uid, $dev, $b['legacy_model'], $b['legacy_activity']);

        $ids = [];
        foreach ($b['requests'] as $r) {
            $ids[] = $r['session_id'];
        }
        foreach ($b['sessions'] as $s) {
            $ids[] = $s['session_id'];
        }
        return (new Plausibility($this->db))->flag($uid, $ids);
    }

    // Alle Listen werden sortiert geschrieben (wie im Go-Server; dort gegen gegenseitiges Sperren).

    /** @param list<array<string, mixed>> $in */
    private function storeAccounts(PDO $pdo, int $uid, array $in, int $now): void
    {
        $m = [];
        foreach ($in as $a) {
            // Bei doppelter Kennung gewinnt die letzte Angabe; eine fehlende Adresse löscht nichts.
            $id = "\0" . $a['account_id'];
            if (isset($m[$id]) && $a['email'] === '' && $a['email_mode'] !== 'off') {
                $a['email'] = $m[$id]['email'];
            }
            $m[$id] = $a;
        }
        ksort($m, SORT_STRING);
        // Neue Konten: off oder fehlende Adresse ergibt NULL. Bekannte: off löscht die Adresse,
        // short/full ohne Adresse lässt sie unverändert.
        $st = $pdo->prepare(
            'insert into accounts (user_id, account_id, email, first_seen_at)'
            . " values (:uid, :id, case when :mode = 'off' then null else nullif(:email, '') end, :now)"
            . ' on conflict (user_id, account_id) do update set'
            . " email = case when :mode = 'off' then null when :email <> '' then :email else accounts.email end",
        );
        foreach ($m as $a) {
            self::run($st, [':uid' => $uid, ':id' => $a['account_id'], ':mode' => $a['email_mode'], ':email' => $a['email'], ':now' => $now]);
        }
    }

    /** @param list<array<string, mixed>> $in */
    private function storeSessions(PDO $pdo, int $uid, int $dev, array $in): void
    {
        $m = [];
        foreach ($in as $s) {
            $id = "\0" . $s['session_id'];
            if (isset($m[$id])) {
                foreach (['project_id', 'cc_version', 'account_id'] as $f) {
                    if ($s[$f] === '') {
                        $s[$f] = $m[$id][$f];
                    }
                }
            }
            $m[$id] = $s;
        }
        ksort($m, SORT_STRING);
        // device_id bleibt, wenn gesetzt, und füllt sich nur, wenn die Plausibilitätsprüfung die Zeile ohne Gerät
        // anlegte; nicht leere Werte ersetzen alte.
        $st = $pdo->prepare(
            'insert into sessions (user_id, session_id, device_id, project_id, cc_version, account_id)'
            . " values (?, ?, ?, nullif(?, ''), nullif(?, ''), nullif(?, ''))"
            . ' on conflict (user_id, session_id) do update set'
            . ' device_id = coalesce(sessions.device_id, excluded.device_id),'
            . ' project_id = coalesce(excluded.project_id, sessions.project_id),'
            . ' cc_version = coalesce(excluded.cc_version, sessions.cc_version),'
            . ' account_id = coalesce(excluded.account_id, sessions.account_id)',
        );
        foreach ($m as $s) {
            self::run($st, [$uid, $s['session_id'], $dev, $s['project_id'], $s['cc_version'], $s['account_id']]);
        }
    }

    private const NUMBERS = ['input', 'output', 'cache_create', 'cache_read', 'cache_1h', 'cache_5m', 'thinking', 'web_search', 'web_fetch'];

    /**
     * Fasst doppelte Schlüssel im Paket zusammen (mergeRequests): Zahlen und Werkzeuge Maximum; stop_reason,
     * account_id und extra nur, wenn der neue Wert nicht leer ist; alles andere erster Wert.
     *
     * @param list<array<string, mixed>> $in
     * @return array<string, array<string, mixed>> sortiert nach (message_id, request_id)
     */
    private static function mergeRequests(array $in): array
    {
        $out = [];
        foreach ($in as $r) {
            // \0 kommt in Kennungen nicht vor: sortiert wie erst message_id, dann request_id.
            $k = $r['message_id'] . "\0" . $r['request_id'];
            if (!isset($out[$k])) {
                $out[$k] = $r;
                continue;
            }
            $o = &$out[$k];
            foreach (self::NUMBERS as $f) {
                $o[$f] = max($o[$f], $r[$f]);
            }
            foreach (['stop_reason', 'account_id'] as $f) {
                if ($r[$f] !== '') {
                    $o[$f] = $r[$f];
                }
            }
            if ($r['extra'] !== []) {
                $o['extra'] = $r['extra'];
            }
            foreach ($r['tools'] as $t => $n) {
                $o['tools'][$t] = max($o['tools'][$t] ?? 0, $n);
            }
            unset($o);
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /** @param list<array<string, mixed>> $in */
    private function storeRequests(PDO $pdo, int $uid, int $dev, array $in): void
    {
        if ($in === []) {
            return;
        }
        // Zahlen: Maximum; ts, Modell, Offset, Sitzung, Gerät: erster Wert;
        // stop_reason, account_id, extra: nur wenn der neue Wert nicht leer ist; eine Zuordnung behält ihr Konto.
        $req = $pdo->prepare(
            'insert into requests (user_id, message_id, request_id, session_id, device_id, ts, utc_offset_min, model,'
            . ' input, output, cache_create, cache_read, cache_1h, cache_5m, thinking, web_search, web_fetch,'
            . ' stop_reason, subagent, account_id, extra)'
            . " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, nullif(?, ''), ?, nullif(?, ''), ?)"
            . ' on conflict (user_id, message_id, request_id) do update set'
            . ' input = max(coalesce(requests.input, 0), excluded.input),'
            . ' output = max(coalesce(requests.output, 0), excluded.output),'
            . ' cache_create = max(coalesce(requests.cache_create, 0), excluded.cache_create),'
            . ' cache_read = max(coalesce(requests.cache_read, 0), excluded.cache_read),'
            . ' cache_1h = max(coalesce(requests.cache_1h, 0), excluded.cache_1h),'
            . ' cache_5m = max(coalesce(requests.cache_5m, 0), excluded.cache_5m),'
            . ' thinking = max(coalesce(requests.thinking, 0), excluded.thinking),'
            . ' web_search = max(coalesce(requests.web_search, 0), excluded.web_search),'
            . ' web_fetch = max(coalesce(requests.web_fetch, 0), excluded.web_fetch),'
            . ' stop_reason = coalesce(excluded.stop_reason, requests.stop_reason),'
            . ' account_id = case when requests.assignment_id is not null then requests.account_id'
            . '                   else coalesce(excluded.account_id, requests.account_id) end,'
            . ' extra = coalesce(excluded.extra, requests.extra)',
        );
        $tool = $pdo->prepare(
            'insert into request_tools (user_id, message_id, request_id, tool, count) values (?, ?, ?, ?, ?)'
            . ' on conflict (user_id, message_id, request_id, tool) do update set'
            . ' count = max(request_tools.count, excluded.count)',
        );
        foreach (self::mergeRequests($in) as $r) {
            $extra = null;
            if ($r['extra'] !== []) {
                // Wie json.Marshal einer Go-Map: Schlüssel sortiert (auch verschachtelt), < > & maskiert; Schlüssel
                // wie "0" bleiben in einem Objekt.
                $extra = GoJson::encode((object) $r['extra'], true);
            }
            $vals = [$uid, $r['message_id'], $r['request_id'], $r['session_id'], $dev, $r['ts_ms'], $r['utc_offset_min'], $r['model']];
            foreach (self::NUMBERS as $f) {
                $vals[] = $r[$f];
            }
            array_push($vals, $r['stop_reason'], $r['subagent'] ? 1 : 0, $r['account_id'], $extra);
            self::run($req, $vals);

            $tools = $r['tools'];
            ksort($tools, SORT_STRING);
            foreach ($tools as $t => $n) {
                self::run($tool, [$uid, $r['message_id'], $r['request_id'], (string) $t, $n]);
            }
        }
    }

    /**
     * Der Altbestand ist ein Stand, kein Zähler: der neue Wert ersetzt den alten; im Paket gewinnt der letzte.
     *
     * @param list<array<string, mixed>> $models
     * @param list<array<string, mixed>> $activity
     */
    private function storeLegacy(PDO $pdo, int $uid, int $dev, array $models, array $activity): void
    {
        if ($models !== []) {
            $m = [];
            foreach ($models as $l) {
                $m[$l['date'] . "\0" . $l['model']] = $l;
            }
            ksort($m, SORT_STRING);
            $st = $pdo->prepare(
                'insert into legacy_model_days (user_id, device_id, date, model, tokens) values (?, ?, ?, ?, ?)'
                . ' on conflict (user_id, device_id, date, model) do update set tokens = excluded.tokens',
            );
            foreach ($m as $l) {
                self::run($st, [$uid, $dev, $l['date'], $l['model'], $l['tokens']]);
            }
        }
        if ($activity !== []) {
            $m = [];
            foreach ($activity as $l) {
                $m["\0" . $l['date']] = $l;
            }
            ksort($m, SORT_STRING);
            $st = $pdo->prepare(
                'insert into legacy_activity_days (user_id, device_id, date, messages, sessions, tool_calls) values (?, ?, ?, ?, ?, ?)'
                . ' on conflict (user_id, device_id, date) do update set'
                . ' messages = excluded.messages, sessions = excluded.sessions, tool_calls = excluded.tool_calls',
            );
            foreach ($m as $l) {
                self::run($st, [$uid, $dev, $l['date'], $l['messages'], $l['sessions'], $l['tool_calls']]);
            }
        }
    }

    /** Führt die vorbereitete Anweisung mit typgerechten Werten aus (Zahlen als INTEGER, nicht als Text). @param array<int|string, mixed> $vals */
    private static function run(PDOStatement $st, array $vals): void
    {
        foreach ($vals as $k => $v) {
            $st->bindValue(is_int($k) ? $k + 1 : $k, $v, match (true) {
                is_int($v) => PDO::PARAM_INT,
                $v === null => PDO::PARAM_NULL,
                default => PDO::PARAM_STR,
            });
        }
        $st->execute();
    }
}
