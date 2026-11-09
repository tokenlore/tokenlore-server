<?php

declare(strict_types=1);

namespace Tokenlore\Devices;

use InvalidArgumentException;
use PDO;
use Tokenlore\Db\Database;
use Tokenlore\Protocol\Limits;
use Tokenlore\Protocol\Validator;
use Tokenlore\Util\Names;
use Tokenlore\Util\Time;

// Geräte eines Nutzers: auflisten, sperren, umbenennen (devices/keys.go, rename.go, handlers/stats.DeviceTotals).
final class Devices
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Alle Signaturschlüssel eines Geräts (32 Byte roh, ohne Doppelte): zuerst der am Geräteschlüssel $keyHash
     * gemeldete (der liefernde), dann die an device_keys, der aktive und dann der neueste zuerst, gesperrte
     * eingeschlossen; danach die früheren aus device_sign_keys, die neuesten zuerst. Ohne $keyHash steht der Schlüssel
     * des aktiven Geräteschlüssels vorn. Unbekanntes Gerät: leere Liste.
     *
     * @param string|null $keyHash Hash des liefernden Geräteschlüssels (hashKey)
     * @return list<string>
     */
    public function signKeys(int $deviceId, ?string $keyHash = null): array
    {
        return self::signKeysIn($this->db->pdo(), $deviceId, $keyHash);
    }

    /**
     * signKeys über eine gegebene Verbindung, auch innerhalb einer laufenden Transaktion (Koppeln, Zusammenlegen).
     *
     * @return list<string>
     */
    public static function signKeysIn(PDO $pdo, int $deviceId, ?string $keyHash = null): array
    {
        $st = $pdo->prepare(
            'select sign_public_key from device_keys where device_id = ? and sign_public_key is not null'
            . ' order by key_hash = ? desc, revoked_at is null desc, created_at desc, rowid desc'
        );
        $st->bindValue(1, $deviceId, PDO::PARAM_INT);
        $st->bindValue(2, $keyHash, $keyHash === null ? PDO::PARAM_NULL : PDO::PARAM_LOB);
        $st->execute();
        $keys = $st->fetchAll(PDO::FETCH_COLUMN);
        $prev = $pdo->prepare('select sign_public_key from device_sign_keys where device_id = ? order by created_at desc, rowid desc');
        $prev->execute([$deviceId]);
        $keys = array_merge($keys, $prev->fetchAll(PDO::FETCH_COLUMN));
        return array_values(array_unique(array_map('strval', $keys)));
    }

    /**
     * Alle Signaturschlüssel des Geräts, dem der Geräteschlüssel mit dem Hash $keyHash jetzt gehört (nach einem
     * Zusammenlegen also das verbliebene Gerät), der an diesem Geräteschlüssel gemeldete zuerst (signKeys). Gesperrte
     * Geräteschlüssel zählen mit; unbekannter Hash: leere Liste.
     *
     * @return list<string>
     */
    public function signKeysOfKey(string $keyHash): array
    {
        $st = $this->db->pdo()->prepare('select device_id from device_keys where key_hash = ?');
        $st->bindValue(1, $keyHash, PDO::PARAM_LOB);
        $st->execute();
        $dev = $st->fetchColumn();
        $st->closeCursor();
        return $dev === false ? [] : $this->signKeys((int) $dev, $keyHash);
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
     * tokens = Eingabe + Ausgabe + Cache-Aufbau + Cache-Lesen. elsewhere: was das Gerät lieferte, aber schon woanders
     * lag ({requests, legacy_days, last_at}; ohne Treffer 0, 0, null).
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
        // Was beim Gerät schon woanders lag (Store: elsewhere_hits): Anfragen, verschiedene Altbestandstage beider Arten,
        // letzter erster Zeitpunkt. Nur Anzahlen und eigene Zeitpunkte, nichts vom anderen Benutzer oder Gerät.
        // „cross join“ hält die Reihenfolge: erst die Geräte des Nutzers, dann ihre Treffer über den Primärschlüssel.
        $hits = $pdo->prepare(
            "select h.device_id,
                    sum(case when h.kind = 'request' then 1 else 0 end) as requests,
                    count(distinct case when h.kind <> 'request' then h.date end) as legacy_days,
                    max(h.first_at) as last_at
               from devices d cross join elsewhere_hits h on h.device_id = d.id
              where d.user_id = ? group by h.device_id"
        );
        $hits->execute([$uid]);
        $elsewhere = [];
        foreach ($hits as $h) {
            $elsewhere[(int) $h['device_id']] = [
                'requests' => (int) $h['requests'],
                'legacy_days' => (int) $h['legacy_days'],
                'last_at' => Time::isoMs((int) $h['last_at'] * 1000),
            ];
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
                // „Plugin veraltet“ nur bei gemeldeter Version; ohne Angabe gibt es nichts zu vergleichen.
                'outdated' => $d['plugin_version'] !== null && Validator::pluginOutdated((string) $d['plugin_version']),
                'last_seen_at' => $d['last_seen_at'] === null ? null : Time::isoMs((int) $d['last_seen_at'] * 1000),
                'created_at' => Time::isoMs((int) $d['created_at'] * 1000),
                'requests' => $t === null ? 0 : (int) $t['n'],
                'tokens' => $t === null ? 0 : (int) $t['tokens'],
                'first_activity' => $t === null ? null : Time::isoMs((int) $t['first_ts']),
                'last_activity' => $t === null ? null : Time::isoMs((int) $t['last_ts']),
                'revoked' => (int) $d['revoked'] === 1,
                'elsewhere' => $elsewhere[(int) $d['id']] ?? ['requests' => 0, 'legacy_days' => 0, 'last_at' => null],
            ];
        }
        return $out;
    }

    /**
     * Sperrt ein Gerät des Nutzers samt Schlüsseln (Grund 'revoked'); wiederholtes Sperren ist harmlos (der erste
     * Zeitpunkt und Grund bleiben). Neu koppeln hebt die Sperre des Geräts wieder auf (Pairing::redeem).
     * false: unbekanntes oder fremdes Gerät.
     */
    public function revoke(int $uid, int $deviceId, int $now): bool
    {
        return (bool) $this->db->tx(static function (PDO $pdo) use ($uid, $deviceId, $now): bool {
            $dev = $pdo->prepare('update devices set revoked_at = coalesce(revoked_at, ?) where id = ? and user_id = ?');
            $dev->execute([$now, $deviceId, $uid]);
            if ($dev->rowCount() === 0) {
                return false;
            }
            $pdo->prepare(
                "update device_keys set revoked_reason = coalesce(revoked_reason, 'revoked'), revoked_at = coalesce(revoked_at, ?)"
                . ' where device_id = ?'
            )->execute([$now, $deviceId]);
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

    /** Mindestzahl überlappender abgeschlossener Tage mit Tokens für einen Hinweis zum Zusammenlegen. */
    public const MERGE_MIN_DAYS = 3;

    /**
     * Paare von Geräten des Nutzers, die wahrscheinlich derselbe Rechner sind: Ihre überlappenden abgeschlossenen
     * Tage des Altbestands sind alle exakt gleich (je Modell die Tokens, dazu Nachrichten, Sitzungen und
     * Werkzeugaufrufe), und mindestens MERGE_MIN_DAYS davon haben Tokens. Nur ein Hinweis; die Daten ändern sich erst
     * mit merge(). Gesperrte Geräte zählen mit.
     *
     * Gleiche Altbestandstage speichert nur das erste Gerät; ein weiteres weist sie ab (Store::storeLegacy) und
     * bekommt dafür Treffer in elsewhere_hits mit seinen eigenen gelieferten Werten und seinem eigenen Abschluss.
     * Verglichen wird daher je Gerät sein Altbestand samt dieser Treffer, als wären sie gespeicherte Zeilen; hat das
     * Gerät die Zeile inzwischen selbst, gilt seine Zeile. Woher der Treffer kam (welches Gerät, welcher Benutzer),
     * spielt keine Rolle: Zwei Geräte mit denselben eigenen Werten haben denselben Altbestand.

     * Ein Tag ist für ein Gerät abgeschlossen, wenn es Altbestand für ihn hat und alle diese Zeilen complete = 1
     * tragen; überlappend heißt: für beide Geräte abgeschlossen. Fehlende Werte zählen als 0, Modelle ohne Tokens
     * fallen beim Vergleich weg. into ist das ältere Gerät (kleinere id), from das neuere.
     *
     * Der Vergleich läuft ganz in SQLite, damit der Speicher in PHP nicht mit dem Altbestand wächst (Altbestand
     * ist je Gerät unbegrenzt). Nur Sprachmittel bis SQLite 3.27 (Requirements::MIN_SQLITE): Fensterfunktionen gibt es ab 3.25,
     * ORDER BY in Aggregaten erst ab 3.44 und FULL JOIN erst ab 3.39, beide also nicht.
     *
     * @return list<array{from:int, into:int}> nach into, dann from
     */
    public function mergeCandidates(int $uid): array
    {
        $st = $this->db->pdo()->prepare(self::MERGE_CANDIDATES_SQL);
        $st->bindValue(':uid', $uid, PDO::PARAM_INT);
        $st->bindValue(':min', self::MERGE_MIN_DAYS, PDO::PARAM_INT);
        $st->execute();
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_NUM) as [$from, $into]) {
            $out[] = ['from' => (int) $from, 'into' => (int) $into];
        }
        return $out;
    }

    /**
     * lm/la: der Altbestand je Gerät des Nutzers samt der Treffer (Modelle bzw. Aktivität) mit ihren eigenen Werten,
     * ein Treffer nur, wenn das Gerät keine gespeicherte Zeile mit demselben Schlüssel hat (Primärschlüssel).
     * Treffer gesucht über den Primärschlüssel von elsewhere_hits (device_id, kind, …). „limit -1“ hält lm und la als
     * eigene Zwischentabellen, die SQLite einmal füllt, statt sie in jede Unterabfrage einzubetten.
     * days: je Gerät und Tag, ob alle Zeilen abgeschlossen sind (c), Zahl (n) und Summe (tok) der Modelle mit Tokens,
     * Nachrichten (m), Sitzungen (s), Werkzeugaufrufe (t).
     * grp: die abgeschlossenen Tage; rep ist je Tag das kleinste Gerät mit denselben Kopfzahlen.
     * cls: die Klasse eines Gerätetags ist das kleinste Gerät, dessen Tag ganz gleich ist (Kopfzahlen und je Modell
     * mit Tokens dieselben Tokens). Gleichheit ist transitiv, also haben zwei Gerätetage genau dann dieselbe Klasse,
     * wenn sie gleich sind. Verglichen wird erst mit rep (der übliche Fall: ein Vergleich je Gerätetag), nur bei
     * Abweichung mit den übrigen Geräten derselben Kopfzahlen. Modelle: Hat jedes Modell mit Tokens von e am selben
     * Tag bei d dieselben Tokens und ist n gleich, sind die Modellmengen gleich.
     * pairs/cand: Paare mit mindestens :min gleichen Tagen mit Tokens; overlap: davon die Paare, deren überlappende
     * Tage alle gleich sind.
     * „limit -1“ hält cls als eigene Zwischentabelle: Ohne würde SQLite die Abfrage in den Verbund in cand einbetten
     * und die Klasse je Paar von Zeilen neu berechnen.
     */
    private const MERGE_CANDIDATES_SQL = <<<'SQL'
        with lm as (
            select l.device_id, l.date, l.model, l.tokens, l.complete
              from legacy_model_days l join devices d on d.id = l.device_id and d.user_id = l.user_id
             where l.user_id = :uid
            union all
            select h.device_id, h.date, h.model, h.tokens, h.complete
              from devices d cross join elsewhere_hits h
             where d.user_id = :uid and h.device_id = d.id and h.kind = 'legacy_model'
               and not exists (select 1 from legacy_model_days o
                                where o.user_id = :uid and o.device_id = h.device_id and o.date = h.date and o.model = h.model)
             limit -1
        ),
        la as (
            select l.device_id, l.date, l.messages, l.sessions, l.tool_calls, l.complete
              from legacy_activity_days l join devices d on d.id = l.device_id and d.user_id = l.user_id
             where l.user_id = :uid
            union all
            select h.device_id, h.date, h.messages, h.sessions, h.tool_calls, h.complete
              from devices d cross join elsewhere_hits h
             where d.user_id = :uid and h.device_id = d.id and h.kind = 'legacy_activity'
               and not exists (select 1 from legacy_activity_days o where o.user_id = :uid and o.device_id = h.device_id and o.date = h.date)
             limit -1
        ),
        days as (
            select device_id, date, min(c) as c, sum(n) as n, sum(tok) as tok, sum(m) as m, sum(s) as s, sum(t) as t
              from (
                select device_id, date, min(complete) as c,
                       sum(case when tokens > 0 then 1 else 0 end) as n,
                       sum(case when tokens > 0 then tokens else 0 end) as tok,
                       0 as m, 0 as s, 0 as t
                  from lm
                 group by device_id, date
                union all
                select device_id, date, complete, 0, 0,
                       coalesce(messages, 0), coalesce(sessions, 0), coalesce(tool_calls, 0)
                  from la
              )
             group by device_id, date
        ),
        grp as (
            select device_id, date, n, min(device_id) over (partition by date, n, tok, m, s, t) as rep
              from days where c = 1
        ),
        cls as (
            select g.device_id, g.date, g.n,
                   case when g.device_id = g.rep or g.n = 0 or g.n = (select count(*) from lm x
                             join lm y on y.device_id = g.device_id and y.date = x.date and y.model = x.model and y.tokens = x.tokens
                            where x.device_id = g.rep and x.date = g.date and x.tokens > 0)
                        then g.rep
                        else coalesce((select min(e.device_id) from grp e
                                        where e.date = g.date and e.rep = g.rep and e.device_id > g.rep and e.device_id < g.device_id
                                          and g.n = (select count(*) from lm x
                             join lm y on y.device_id = g.device_id and y.date = x.date and y.model = x.model and y.tokens = x.tokens
                            where x.device_id = e.device_id and x.date = g.date and x.tokens > 0)), g.device_id)
                   end as cls
              from grp g
             limit -1
        ),
        cand as (
            select x.device_id as a, y.device_id as b, count(*) as k
              from cls x join cls y on y.date = x.date and y.cls = x.cls and y.device_id > x.device_id
             group by x.device_id, y.device_id
            having sum(case when x.n > 0 then 1 else 0 end) >= :min
        )
        select c.b, c.a
          from cand c
          join grp x on x.device_id = c.a
          join grp y on y.device_id = c.b and y.date = x.date
         group by c.a, c.b, c.k
        having count(*) = c.k
         order by c.a, c.b
        SQL;

    /**
     * Legt Gerät $from in Gerät $into zusammen, beide vom Nutzer, in einer Transaktion: Anfragen und Sitzungen gehen
     * an $into; von der Vorgeschichte bleibt je Tag die Zeile mit der größeren Summe der Tokens als Ganzes (bei
     * Gleichstand die von $into), samt Modellen und Aktivität des Tags; die Treffer „schon woanders“
     * (elsewhere_hits) gehen an $into, ein gleicher Schlüssel bleibt eine Zeile (je Feld das Maximum, der frühere
     * erste Zeitpunkt), und Altbestandstreffer, deren Tag $into danach selbst mit denselben Werten führt, fallen weg;
     * Schlüssel (aktive bleiben aktiv), frühere Signaturschlüssel (device_sign_keys) und Kennungen gehen an $into,
     * sodass das Plugin von $from ohne Neukoppeln an $into liefert; danach hält capSignKeys die Grenze, und nur der
     * zuletzt gemeldete aktuelle Signaturschlüssel ist sicher (die übrigen zählen als frühere); offene Kopplungscodes für $from und seine Liefersperre fallen weg; $from wird
     * gelöscht. Hat $into danach einen aktiven Schlüssel, ist seine Sperre aufgehoben, sonst bleibt sie.
     *
     * Anfragen und Sitzungen sind über alle Benutzer eindeutig (ohne Benutzer und Gerät im Schlüssel); dieselbe Anfrage
     * zweier Geräte ist also schon beim Liefern eine Zeile, und das Umhängen erzeugt keinen Konflikt.
     *
     * false: $from gleich $into, unbekanntes oder fremdes Gerät; dann ändert sich nichts.
     */
    public function merge(int $uid, int $into, int $from): bool
    {
        if ($into === $from) {
            return false;
        }
        return (bool) $this->db->tx(static function (PDO $pdo) use ($uid, $into, $from): bool {
            $own = $pdo->prepare('select count(*) from devices where user_id = ? and id in (?, ?)');
            $own->execute([$uid, $into, $from]);
            if ((int) $own->fetchColumn() !== 2) {
                return false;
            }
            $run = static function (string $sql, array $args) use ($pdo): void {
                $pdo->prepare($sql)->execute($args);
            };
            $run('update requests set device_id = ? where user_id = ? and device_id = ?', [$into, $uid, $from]);
            $run('update sessions set device_id = ? where user_id = ? and device_id = ?', [$into, $uid, $from]);
            // Vorgeschichte: Werte und Signatur gehören immer zu genau einer Zeile. Haben beide Geräte denselben Tag,
            // bleibt der Tag des Geräts mit der größeren Summe der Tokens als Ganzes (Zeile, Modelle, Aktivität), bei
            // Gleichstand der von $into; der andere fällt weg. Danach gehen die Tage von $from an $into.
            $sums = $pdo->prepare(
                'select date, sum(tokens) from (select date, coalesce(tokens, 0) as tokens from legacy_model_days where user_id = :uid and device_id = :dev'
                . ' union all select date, 0 from legacy_activity_days where user_id = :uid and device_id = :dev'
                . ' union all select date, 0 from legacy_day_lines where user_id = :uid and device_id = :dev) group by date',
            );
            $daySums = [];
            foreach ([$into, $from] as $dev) {
                $sums->execute([':uid' => $uid, ':dev' => $dev]);
                $daySums[$dev] = $sums->fetchAll(PDO::FETCH_KEY_PAIR);
            }
            foreach ($daySums[$from] as $date => $sum) {
                if (!isset($daySums[$into][$date])) {
                    continue;
                }
                $loser = (int) $sum > (int) $daySums[$into][$date] ? $into : $from;
                foreach (['legacy_day_lines', 'legacy_model_days', 'legacy_activity_days'] as $t) {
                    $run("delete from $t where user_id = ? and device_id = ? and date = ?", [$uid, $loser, (string) $date]);
                }
            }
            foreach (['legacy_day_lines', 'legacy_model_days', 'legacy_activity_days'] as $t) {
                $run("update $t set device_id = ? where user_id = ? and device_id = ?", [$into, $uid, $from]);
            }
            // Treffer „schon woanders“ wie Store::storeHits: gleicher Schlüssel einmal, je Feld das Maximum (NULL ersetzt
            // keinen Wert), complete das Maximum, first_at der frühere Zeitpunkt.
            $set = [];
            foreach (['tokens', 'messages', 'sessions', 'tool_calls'] as $f) {
                $set[] = " $f = max(coalesce(elsewhere_hits.$f, excluded.$f), coalesce(excluded.$f, elsewhere_hits.$f))";
            }
            $run(
                'insert into elsewhere_hits (device_id, kind, date, model, message_id, request_id, tokens, messages, sessions, tool_calls, complete, first_at)'
                . ' select ?, kind, date, model, message_id, request_id, tokens, messages, sessions, tool_calls, complete, first_at'
                . ' from elsewhere_hits where device_id = ? and true'
                . ' on conflict (device_id, kind, date, model, message_id, request_id) do update set' . implode(',', $set) . ','
                . ' complete = max(elsewhere_hits.complete, excluded.complete),'
                . ' first_at = min(elsewhere_hits.first_at, excluded.first_at)',
                [$into, $from],
            );
            $run('delete from elsewhere_hits where device_id = ?', [$from]);
            // Treffer, die nur auf eines der beiden Geräte zeigten, fallen weg: $into führt den Tag jetzt selbst mit
            // genau den Werten des Treffers (verglichen mit „is“, NULL gleich NULL). Anfragen betreffen nur fremde
            // Benutzer und bleiben.
            $run(
                "delete from elsewhere_hits where device_id = ? and kind = 'legacy_model' and exists ("
                . ' select 1 from legacy_model_days m where m.user_id = ? and m.device_id = elsewhere_hits.device_id'
                . ' and m.date = elsewhere_hits.date and m.model = elsewhere_hits.model and m.tokens is elsewhere_hits.tokens)',
                [$into, $uid],
            );
            $run(
                "delete from elsewhere_hits where device_id = ? and kind = 'legacy_activity' and exists ("
                . ' select 1 from legacy_activity_days d where d.user_id = ? and d.device_id = elsewhere_hits.device_id'
                . ' and d.date = elsewhere_hits.date and d.messages is elsewhere_hits.messages'
                . ' and d.sessions is elsewhere_hits.sessions and d.tool_calls is elsewhere_hits.tool_calls)',
                [$into, $uid],
            );
            $run('update device_keys set device_id = ? where device_id = ?', [$into, $from]);
            // Frühere Signaturschlüssel ziehen mit; ein Schlüssel gehört genau einem Gerät, Doppelte gibt es also nicht.
            $run('update device_sign_keys set device_id = ? where device_id = ?', [$into, $from]);
            self::capSignKeys($pdo, $into);
            $run('update device_sources set device_id = ? where user_id = ? and device_id = ?', [$into, $uid, $from]);
            // Offene Codes für $from fallen weg; eingelöste bleiben als Verlauf bei $into.
            $run('delete from pair_codes where user_id = ? and device_id = ? and used_at is null', [$uid, $from]);
            $run('update pair_codes set device_id = ? where user_id = ? and device_id = ?', [$into, $uid, $from]);
            $run('delete from device_locks where device_id = ?', [$from]);
            // Zuletzt gesehen: der spätere Zeitpunkt beider Geräte (max() übergeht NULL).
            $run('update devices set last_seen_at = (select max(last_seen_at) from devices where id in (?, ?)) where id = ?', [$into, $from, $into]);
            $run('delete from devices where id = ? and user_id = ?', [$from, $uid]);
            $run(
                'update devices set revoked_at = null where id = ?'
                . ' and exists (select 1 from device_keys where device_id = ? and revoked_at is null)',
                [$into, $into],
            );
            return true;
        });
    }

    /**
     * Hält das Gerät unter Limits::MAX_SIGN_KEYS_PER_DEVICE (nach Koppeln und Zusammenlegen). Der zuletzt gemeldete
     * aktuelle Schlüssel (am neuesten aktiven Geräteschlüssel mit Signaturschlüssel) bleibt immer. Alle übrigen gelten
     * als frühere, auch die an anderen aktiven Geräteschlüsseln nach einem Zusammenlegen (Entscheidung Z8 a); von ihnen
     * bleiben die zuletzt gemeldeten, bis die Grenze erreicht ist. Die ältesten fallen weg: aus device_sign_keys
     * gelöscht, an Geräteschlüsseln geleert. Zeilen mit einem so entfernten Schlüssel nimmt der Server von diesem Gerät
     * nicht mehr an; gespeicherte Zeilen bleiben.
     */
    public static function capSignKeys(PDO $pdo, int $deviceId): void
    {
        $cur = $pdo->prepare(
            'select sign_public_key from device_keys where device_id = ? and revoked_at is null and sign_public_key is not null'
            . ' order by created_at desc, rowid desc limit 1'
        );
        $cur->execute([$deviceId]);
        $current = $cur->fetchColumn();
        $cur->closeCursor();
        $keep = $current === false ? [] : [(string) $current => true];
        // Gleich alt: der Schlüssel am Geräteschlüssel ist der neuere (die früheren hat er beim selben Koppeln ersetzt),
        // in device_sign_keys der zuletzt gesendete (das Plugin sendet die ältesten zuerst).
        $prev = $pdo->prepare(
            'select sign_public_key from ('
            . ' select sign_public_key, created_at, 1 as at_key, rowid as r from device_keys'
            . '  where device_id = :dev and sign_public_key is not null'
            . ' union all select sign_public_key, created_at, 0, rowid from device_sign_keys where device_id = :dev'
            . ') order by created_at desc, at_key desc, r desc'
        );
        $prev->execute([':dev' => $deviceId]);
        $drop = [];
        foreach ($prev->fetchAll(PDO::FETCH_COLUMN) as $key) {
            $key = (string) $key;
            if (isset($keep[$key]) || isset($drop[$key])) {
                continue;
            }
            if (count($keep) < Limits::MAX_SIGN_KEYS_PER_DEVICE) {
                $keep[$key] = true;
            } else {
                $drop[$key] = true;
            }
        }
        $del = $pdo->prepare('delete from device_sign_keys where device_id = ? and sign_public_key = ?');
        $clear = $pdo->prepare('update device_keys set sign_public_key = null where device_id = ? and sign_public_key = ?');
        foreach (array_keys($drop) as $key) {
            foreach ([$del, $clear] as $st) {
                $st->bindValue(1, $deviceId, PDO::PARAM_INT);
                $st->bindValue(2, (string) $key, PDO::PARAM_LOB);
                $st->execute();
            }
        }
    }
}
