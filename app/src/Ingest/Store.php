<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

use PDO;
use PDOStatement;
use Tokenlore\Db\Database;
use Tokenlore\Util\GoJson;

// Speichert ein geprüftes Paket in einer Transaktion. Jede schreibende Anweisung ist an den liefernden Benutzer
// gebunden (user_id aus dem Geräteschlüssel, elsewhere_hits über sein Gerät); nur die Prüfungen auf Fremdes und gleiche
// Vorgeschichte lesen über alle Benutzer.
// Anfragen und Vorgeschichte-Tage kommen als signierte Zeilen (z, s); gespeichert wird je Zeile z und s unverändert
// samt der daraus gelesenen Werte. Eine gespeicherte Zeile wird nie ersetzt: Kommt sie erneut, bleibt die erste samt
// Signatur, ein Maximum über zwei Zeilen gäbe es zu keiner Signatur (Abschnitt „Wiederholte Lieferung“).
// Jede Anfrage und jede Sitzung liegt genau einmal auf dem Server, über alle Benutzer: wer zuerst liefert, besitzt
// sie. Was einem anderen Benutzer gehört, wird übergangen und nur gezählt (elsewhere_hits); ebenso Vorgeschichte-Tage,
// die ein anderes Gerät schon mit genau denselben Modellen und Tokens hat.
final class Store
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Speichert das Paket (Ergebnis von Decoder::validate) und setzt Gerätedaten und last_seen_at. Ein BEGIN IMMEDIATE
     * je Paket; bei einem Fehler bleibt nichts davon stehen.
     * Antwort: gelieferte Anzahlen, die Anfragen, die dieser Benutzer schon hatte (known_requests), die markierten
     * Sitzungen des Pakets, die Zahl der Anfragen, die schon einem anderen Benutzer gehören (oder in dessen Sitzung
     * liegen), und die abgewiesenen Vorgeschichte-Tage; ohne Zahlen, Benutzer oder Gerät des anderen.
     *
     * @param array<string, mixed> $batch
     * @return array{requests:int, legacy_days:int, sessions:int, accounts:int, known_requests:int,
     *               flagged_sessions:list<string>, elsewhere_requests:int, legacy_rejected_days:list<string>}
     * @param string|null $keyHash Hash des liefernden Schlüssels (Devices::hashKey): gilt nur dieser Schlüssel, nicht
     *        irgendein Schlüssel des Geräts; so scheitert ein Schlüssel, der während der Lieferung durch Neukoppeln
     *        gesperrt wurde, obwohl das Gerät einen neuen hat. null: irgendein gültiger Schlüssel des Geräts genügt.
     * @throws DeviceRevoked wenn Gerät, Schlüssel oder Konto inzwischen gesperrt sind oder das Gerät nicht dem Nutzer gehört
     */
    public function save(int $uid, int $deviceId, array $batch, int $nowMs, ?string $keyHash = null): array
    {
        $pdo = $this->db->pdo();
        // Eigene Transaktion statt Database::tx: das Zurückrollen hängt so nicht an PDO::inTransaction(), das ein
        // per exec gestartetes BEGIN unter PHP 8.2 nicht erkennt.
        $pdo->exec('BEGIN IMMEDIATE');
        try {
            $res = $this->write($pdo, $uid, $deviceId, $batch, intdiv($nowMs, 1000), $keyHash);
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
            'legacy_days' => count($batch['legacy_days']),
            'sessions' => count($batch['sessions']),
            'accounts' => count($batch['accounts']),
        ] + $res;
    }

    /**
     * @param array<string, mixed> $b
     * @return array{known_requests:int, flagged_sessions:list<string>, elsewhere_requests:int, legacy_rejected_days:list<string>}
     */
    private function write(PDO $pdo, int $uid, int $dev, array $b, int $now, ?string $keyHash): array
    {
        $d = $b['device'];
        $st = $pdo->prepare(
            'update devices set os = ?, arch = ?, tz = ?, plugin_version = ?, last_seen_at = ?'
            . ' where id = ? and user_id = ? and revoked_at is null'
            . ' and exists (select 1 from device_keys k where k.device_id = devices.id and k.revoked_at is null'
            . ($keyHash === null ? '' : ' and k.key_hash = cast(? as blob)') . ')'
            . ' and exists (select 1 from users u where u.id = devices.user_id and u.disabled_at is null)',
        );
        $args = [$d['os'], $d['arch'], $d['tz'], $d['plugin_version'], $now, $dev, $uid];
        if ($keyHash !== null) {
            $args[] = $keyHash;
        }
        self::run($st, $args);
        if ($st->rowCount() !== 1) {
            throw new DeviceRevoked();
        }

        $requests = self::firstPerKey($b['requests']);
        $ids = [];
        foreach ($requests as $r) {
            $ids[$r['session_id']] = true;
        }
        foreach ($b['sessions'] as $s) {
            $ids[$s['session_id']] = true;
        }
        $foreignSessions = $this->foreignSessions($pdo, $uid, array_keys($ids));
        $foreign = $this->foreignRequests($pdo, $uid, $requests, $foreignSessions);
        $own = array_diff_key($requests, $foreign);

        $this->storeSessions($pdo, $uid, $dev, array_values(array_filter(
            $b['sessions'],
            static fn(array $s): bool => !isset($foreignSessions[$s['session_id']]),
        )));
        $known = $this->storeRequests($pdo, $uid, $dev, $own);
        $this->storeAccounts($pdo, $uid, $b['accounts'], $now);
        [$rejected, $hits] = $this->storeLegacy($pdo, $uid, $dev, $b['legacy_days'], $now);
        foreach (array_keys($foreign) as $k) {
            $hits[] = ['kind' => 'request', 'message_id' => $requests[$k]['message_id'], 'request_id' => $requests[$k]['request_id']];
        }
        $this->storeHits($pdo, $dev, $hits, $now);

        $own = array_values(array_filter(array_map('strval', array_keys($ids)), static fn(string $id): bool => !isset($foreignSessions[$id])));
        return [
            'known_requests' => $known,
            'flagged_sessions' => (new Plausibility($this->db))->flag($uid, $own),
            'elsewhere_requests' => count($foreign),
            'legacy_rejected_days' => $rejected,
        ];
    }

    /**
     * Sitzungen unter $ids, die einem anderen Benutzer gehören: ihre Zeile in sessions oder eine gespeicherte Anfrage
     * darin gehört ihm. Als JSON-Liste übergeben (json_each): keine Grenze für die Zahl der Platzhalter.
     *
     * @param list<int|string> $ids
     * @return array<string, true>
     */
    private function foreignSessions(PDO $pdo, int $uid, array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        $json = json_encode(array_map('strval', $ids), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $st = $pdo->prepare(
            'select s.session_id from sessions s where s.session_id in (select value from json_each(:ids)) and s.user_id <> :uid'
            . ' union select r.session_id from requests r where r.session_id in (select value from json_each(:ids)) and r.user_id <> :uid',
        );
        self::run($st, [':ids' => $json, ':uid' => $uid]);
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $id) {
            $out[(string) $id] = true;
        }
        return $out;
    }

    /**
     * Anfragen, die schon einem anderen Benutzer gehören oder in einer fremden Sitzung liegen.
     *
     * @param array<string, array<string, mixed>> $requests aus mergeRequests
     * @param array<string, true> $foreignSessions
     * @return array<string, true> Schlüssel wie in $requests
     */
    private function foreignRequests(PDO $pdo, int $uid, array $requests, array $foreignSessions): array
    {
        $out = [];
        $keys = [];
        foreach ($requests as $k => $r) {
            if (isset($foreignSessions[$r['session_id']])) {
                $out[$k] = true;
            } else {
                $keys[] = [$r['message_id'], $r['request_id']];
            }
        }
        if ($keys !== []) {
            $st = $pdo->prepare(
                'select r.message_id, r.request_id from json_each(:keys) j'
                . " join requests r on r.message_id = json_extract(j.value, '$[0]') and r.request_id = json_extract(j.value, '$[1]')"
                . ' where r.user_id <> :uid',
            );
            self::run($st, [':keys' => json_encode($keys, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), ':uid' => $uid]);
            foreach ($st->fetchAll(PDO::FETCH_NUM) as [$m, $r]) {
                $out[$m . "\0" . $r] = true;
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /**
     * Zählt Übergangenes je Gerät in elsewhere_hits. Ein erneuter Treffer lässt first_at stehen; die eigenen Werte
     * abgewiesener Tage gehen je Feld per Maximum ein wie in storeLegacy (NULL ersetzt keinen Wert), complete bleibt 1.
     *
     * @param list<array<string, mixed>> $hits je Treffer kind und die Teile des Schlüssels, bei Altbestand die Werte
     */
    private function storeHits(PDO $pdo, int $dev, array $hits, int $now): void
    {
        if ($hits === []) {
            return;
        }
        $set = [];
        foreach (['tokens', 'messages', 'sessions', 'tool_calls'] as $f) {
            $set[] = " $f = max(coalesce(elsewhere_hits.$f, excluded.$f), coalesce(excluded.$f, elsewhere_hits.$f))";
        }
        $st = $pdo->prepare(
            'insert into elsewhere_hits (device_id, kind, date, model, message_id, request_id, tokens, messages, sessions, tool_calls, complete, first_at)'
            . ' values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            . ' on conflict (device_id, kind, date, model, message_id, request_id) do update set' . implode(',', $set) . ','
            . ' complete = max(elsewhere_hits.complete, excluded.complete)',
        );
        foreach ($hits as $h) {
            self::run($st, [
                $dev, $h['kind'], $h['date'] ?? '', $h['model'] ?? '', $h['message_id'] ?? '', $h['request_id'] ?? '',
                $h['tokens'] ?? null, $h['messages'] ?? null, $h['sessions'] ?? null, $h['tool_calls'] ?? null,
                $h['complete'] ?? 0, $now,
            ]);
        }
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
        // Ein Konto gehört nur zum Benutzer, wenn er eine eigene Anfrage oder Sitzung damit hat (gespeichert, auch aus
        // diesem Paket, das vorher geschrieben wurde); sonst bleibt es weg. Wer nur Anfragen eines anderen liefert,
        // bekommt so kein fremdes Konto in seine Liste.
        $known = $pdo->prepare(
            'select exists (select 1 from accounts where user_id = :uid and account_id = :id)'
            . ' or exists (select 1 from requests where user_id = :uid and account_id = :id)'
            . ' or exists (select 1 from sessions where user_id = :uid and account_id = :id)',
        );
        // Neue Konten: off oder fehlende Adresse ergibt NULL. Bekannte: off löscht die Adresse,
        // short/full ohne Adresse lässt sie unverändert.
        $st = $pdo->prepare(
            'insert into accounts (user_id, account_id, email, first_seen_at)'
            . " values (:uid, :id, case when :mode = 'off' then null else nullif(:email, '') end, :now)"
            . ' on conflict (user_id, account_id) do update set'
            . " email = case when :mode = 'off' then null when :email <> '' then :email else accounts.email end",
        );
        foreach ($m as $a) {
            self::run($known, [':uid' => $uid, ':id' => $a['account_id']]);
            if ((int) $known->fetchColumn() !== 1) {
                continue;
            }
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
                foreach (['cc_version', 'account_id'] as $f) {
                    if ($s[$f] === '') {
                        $s[$f] = $m[$id][$f];
                    }
                }
            }
            $m[$id] = $s;
        }
        ksort($m, SORT_STRING);
        // device_id bleibt, wenn gesetzt, und füllt sich nur, wenn die Plausibilitätsprüfung die Zeile ohne Gerät
        // anlegte; nicht leere Werte ersetzen alte. Fremde Sitzungen sind schon aussortiert; die Bedingung im Update
        // schützt die Zeile eines anderen Benutzers trotzdem.
        $st = $pdo->prepare(
            'insert into sessions (user_id, session_id, device_id, cc_version, account_id)'
            . " values (?, ?, ?, nullif(?, ''), nullif(?, ''))"
            . ' on conflict (session_id) do update set'
            . ' device_id = coalesce(sessions.device_id, excluded.device_id),'
            . ' cc_version = coalesce(excluded.cc_version, sessions.cc_version),'
            . ' account_id = coalesce(excluded.account_id, sessions.account_id)'
            . ' where sessions.user_id = excluded.user_id',
        );
        foreach ($m as $s) {
            self::run($st, [$uid, $s['session_id'], $dev, $s['cc_version'], $s['account_id']]);
        }
    }

    private const NUMBERS = ['input', 'output', 'cache_create', 'cache_read', 'cache_1h', 'cache_5m', 'thinking', 'web_search', 'web_fetch'];

    /**
     * Je Schlüssel (message_id, request_id) die erste Anfrage des Pakets; spätere mit demselben Schlüssel fallen weg,
     * wie eine Wiederholung über zwei Lieferungen.
     *
     * @param list<array<string, mixed>> $in
     * @return array<string, array<string, mixed>> sortiert nach (message_id, request_id)
     */
    private static function firstPerKey(array $in): array
    {
        $out = [];
        foreach ($in as $r) {
            // \0 kommt in Kennungen nicht vor: sortiert wie erst message_id, dann request_id.
            $out[$r['message_id'] . "\0" . $r['request_id']] ??= $r;
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /**
     * Speichert neue Anfragen samt z und s; eine schon gespeicherte bleibt unverändert, mit ihren Werkzeugen.
     *
     * @param array<string, array<string, mixed>> $in aus firstPerKey, ohne fremde Anfragen
     * @return int Zahl der Anfragen, die schon gespeichert waren (known_requests)
     */
    private function storeRequests(PDO $pdo, int $uid, int $dev, array $in): int
    {
        if ($in === []) {
            return 0;
        }
        // Der Besitz einer Sitzung steht immer in sessions: fehlt die Zeile, legt die erste Anfrage sie an.
        $sess = $pdo->prepare(
            'insert into sessions (user_id, session_id, device_id) values (?, ?, ?)'
            . ' on conflict (session_id) do update set device_id = coalesce(sessions.device_id, excluded.device_id)'
            . ' where sessions.user_id = excluded.user_id',
        );
        $seen = [];
        foreach ($in as $r) {
            if (!isset($seen[$r['session_id']])) {
                $seen[$r['session_id']] = true;
                self::run($sess, [$uid, $r['session_id'], $dev]);
            }
        }
        $req = $pdo->prepare(
            'insert into requests (user_id, message_id, request_id, session_id, device_id, ts, utc_offset_min, model,'
            . ' input, output, cache_create, cache_read, cache_1h, cache_5m, thinking, web_search, web_fetch,'
            . ' stop_reason, subagent, account_id, extra, z, s)'
            . " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, nullif(?, ''), ?, nullif(?, ''), ?, ?, ?)"
            . ' on conflict (message_id, request_id) do nothing',
        );
        $tool = $pdo->prepare('insert into request_tools (user_id, message_id, request_id, tool, count) values (?, ?, ?, ?, ?)');
        $known = 0;
        foreach ($in as $r) {
            $extra = null;
            if ($r['extra'] !== []) {
                // Wie json.Marshal einer Go-Map: Schlüssel sortiert, < > & maskiert; Schlüssel wie "0" bleiben in einem Objekt.
                $extra = GoJson::encode((object) $r['extra'], true);
            }
            $vals = [$uid, $r['message_id'], $r['request_id'], $r['session_id'], $dev, $r['ts_ms'], $r['utc_offset_min'], $r['model']];
            foreach (self::NUMBERS as $f) {
                $vals[] = $r[$f];
            }
            array_push($vals, $r['stop_reason'], $r['subagent'] ? 1 : 0, $r['account_id'], $extra, $r['z'], $r['s']);
            self::run($req, $vals);
            if ($req->rowCount() !== 1) {
                // Schon gespeichert, von diesem Benutzer (fremde sind vorher aussortiert): bleibt wie es ist.
                $known++;
                continue;
            }
            $tools = $r['tools'];
            ksort($tools, SORT_STRING);
            foreach ($tools as $t => $n) {
                self::run($tool, [$uid, $r['message_id'], $r['request_id'], (string) $t, $n]);
            }
        }
        return $known;
    }

    /**
     * Speichert die Vorgeschichte-Tage (Abschnitt „Vorgeschichte auf dem Server“). Je Tag die erste Zeile des Pakets;
     * hat das Gerät für den Tag schon eine Zeile, bleibt diese als Ganzes und nur complete kann von 0 auf 1 gehen
     * (complete_before der gespeicherten Zeile gegen den heutigen Tag). Sonst kommt die Zeile in legacy_day_lines,
     * ihre Modelle in legacy_model_days und ihre Aktivität in legacy_activity_days.
     *
     * Abweisen: Hat das Gerät für den Tag noch keine Zeile und hat ein anderes Gerät, gleich welchen Benutzers (auch
     * gesperrt), für denselben Tag genau dieselben Modelle mit denselben Tokens, ist es dieselbe Vorgeschichte (etwa
     * aus einer Kopie von ~/.claude) und wird nicht gespeichert. Ein Tag ohne Modelle oder nur mit Tokens 0 wird nie
     * abgewiesen. Abgewiesenes kommt mit den eigenen Werten und dem eigenen Abschluss als Treffer zurück (storeHits):
     * je Modell ein Treffer legacy_model, die Aktivität als legacy_activity.
     *
     * complete: Tag vor complete_before der Zeile und vor heute (UTC); einmal 1, bleibt 1.
     *
     * @param list<array<string, mixed>> $days aus Decoder::validate
     * @return array{0: list<string>, 1: list<array<string, mixed>>} abgewiesene Tage, sortiert, und die Treffer dazu
     */
    private function storeLegacy(PDO $pdo, int $uid, int $dev, array $days, int $now): array
    {
        if ($days === []) {
            return [[], []];
        }
        $today = gmdate('Y-m-d', $now);
        $complete = static function (string $date, ?string $before) use ($today): int {
            // Beide Seiten sind YYYY-MM-DD; die Textordnung ist die Zeitordnung.
            return $before !== null && $date < min($before, $today) ? 1 : 0;
        };
        $m = [];
        foreach ($days as $l) {
            $m["\0" . $l['date']] ??= $l;
        }
        ksort($m, SORT_STRING);

        $has = $pdo->prepare('select exists (select 1 from legacy_day_lines where user_id = ? and device_id = ? and date = ?)');
        // Ein anderes Gerät hat am Tag genau dieselben Modelle: gleich viele Zeilen, und jede passt zu einem Modell des
        // Pakets (Modell und Tokens).
        $same = $pdo->prepare(
            'select exists (select 1 from legacy_model_days o where o.date = :date and o.device_id <> :dev'
            . ' group by o.device_id having count(*) = :n and sum(exists (select 1 from json_each(:models) j'
            . ' where j.key = o.model and j.value is o.tokens)) = :n)',
        );
        // Abschluss nachtragen: complete_before steht in der gespeicherten Zeile.
        $mark = [];
        foreach (['legacy_model_days', 'legacy_activity_days'] as $t) {
            $mark[] = $pdo->prepare(
                "update $t set complete = 1 where user_id = :uid and device_id = :dev and date = :date and complete = 0"
                . ' and exists (select 1 from legacy_day_lines l where l.user_id = :uid and l.device_id = :dev and l.date = :date'
                . " and l.date < min(json_extract(l.z, '$.complete_before'), :today))",
            );
        }
        $line = $pdo->prepare('insert into legacy_day_lines (user_id, device_id, date, z, s) values (?, ?, ?, ?, ?)');
        $model = $pdo->prepare('insert into legacy_model_days (user_id, device_id, date, model, tokens, complete) values (?, ?, ?, ?, ?, ?)');
        $activity = $pdo->prepare(
            'insert into legacy_activity_days (user_id, device_id, date, messages, sessions, tool_calls, complete) values (?, ?, ?, ?, ?, ?, ?)',
        );

        $rejected = [];
        $hits = [];
        foreach ($m as $l) {
            $date = $l['date'];
            $done = $complete($date, $l['complete_before']);
            self::run($has, [$uid, $dev, $date]);
            if ((int) $has->fetchColumn() === 1) {
                foreach ($mark as $st) {
                    self::run($st, [':uid' => $uid, ':dev' => $dev, ':date' => $date, ':today' => $today]);
                }
                continue;
            }
            $models = $l['models'];
            ksort($models, SORT_STRING);
            if (array_filter($models, static fn(int $t): bool => $t > 0) !== []) {
                self::run($same, [
                    ':date' => $date, ':dev' => $dev, ':n' => count($models),
                    ':models' => json_encode((object) $models, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                ]);
                if ((int) $same->fetchColumn() === 1) {
                    $rejected[] = $date;
                    foreach ($models as $name => $tokens) {
                        $hits[] = ['kind' => 'legacy_model', 'date' => $date, 'model' => (string) $name, 'tokens' => $tokens, 'complete' => $done];
                    }
                    if ($l['activity'] !== null) {
                        $hits[] = ['kind' => 'legacy_activity', 'date' => $date, 'complete' => $done] + $l['activity'];
                    }
                    continue;
                }
            }
            self::run($line, [$uid, $dev, $date, $l['z'], $l['s']]);
            foreach ($models as $name => $tokens) {
                self::run($model, [$uid, $dev, $date, (string) $name, $tokens, $done]);
            }
            if ($l['activity'] !== null) {
                $a = $l['activity'];
                self::run($activity, [$uid, $dev, $date, $a['messages'], $a['sessions'], $a['tool_calls'], $done]);
            }
        }
        return [$rejected, $hits];
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
