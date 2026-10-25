<?php

declare(strict_types=1);

namespace Tokenlore\Stats;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use PDOStatement;
use Tokenlore\Db\Database;
use Tokenlore\Protocol\Limits;
use Tokenlore\Util\Parse;
use Tokenlore\Util\Sql;
use Tokenlore\Util\Time;

// Kennzahlen je Nutzer und Filter aus den Einzelanfragen (wie internal/stats und stats_handlers.go im Go-Server).
// Der Altbestand (stats-cache) wird nie mit Einzelanfragen summiert, sondern getrennt ausgewiesen.
//
// Zeitrechnung: requests.ts sind Unix-Millisekunden. Tagesuhr, Wochenrhythmus, aktive Tage und Serien zählen in der
// Ortszeit der Arbeit (ts plus utc_offset_min der Anfrage). Die Tagesreihe zählt in der Zeitzone des Betrachters;
// SQLite kennt keine Zeitzonen, deshalb rechnet PHP die Abschnitte gleichen Versatzes der Zone im Zeitraum der Daten
// aus (DateTimeZone::getTransitions), und die Abfrage ordnet jede Anfrage ihrem Abschnitt zu.
//
// Ein Filter ist ein Feld wie NO_FILTER: from/to in Unix-Sekunden (from inklusive, to exklusiv), tz ein IANA-Name.
final class Stats
{
    public const NO_FILTER = [
        'model' => '', 'account' => '', 'unknown_account' => false, 'device' => 0, 'from' => null, 'to' => null, 'tz' => 'UTC',
    ];

    /** Lokaler Tag der Arbeit (wie die View daily_model_usage). */
    public const LOCAL_DAY = "date(r.ts / 1000 + r.utc_offset_min * 60, 'unixepoch')";
    /** Ortszeit der Arbeit in Unix-Sekunden. */
    private const LOCAL_SEC = '(r.ts / 1000 + r.utc_offset_min * 60)';
    public const TOKENS = '(coalesce(r.input, 0) + coalesce(r.output, 0) + coalesce(r.cache_create, 0) + coalesce(r.cache_read, 0))';

    /** Tage je Zeitraum-Schlüssel; 0 = alles. */
    private const RANGE_DAYS = ['7d' => 7, '30d' => 30, 'all' => 0];
    private const TZ_PATTERN = '/^[A-Za-z0-9_+\-\/]{1,64}\z/';

    /** @var array<string,int>|null */
    private static ?array $zones = null;

    private readonly Closure $clock;

    /** @param (callable(): int)|null $clock Unix-Sekunden (Standard: time()) */
    public function __construct(private readonly Database $db, ?callable $clock = null)
    {
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
    }

    /**
     * Antwort von GET /api/stats für einen Nutzer: liest range, tz und höchstens einen Filter aus $query
     * (Abfrageparameter wie $_GET). Wirft ParamError bei ungültigen Parametern.
     *
     * @param array<string,mixed> $query
     * @return array<string,mixed>
     */
    public function forUser(int $uid, array $query): array
    {
        return $this->forUsers([$uid], $query);
    }

    /**
     * Wie forUser, aber summiert über mehrere Nutzer (Team-Übersicht). Sitzungen zählen je Nutzer getrennt.
     *
     * @param list<int> $uids
     * @param array<string,mixed> $query
     * @return array<string,mixed>
     */
    public function forUsers(array $uids, array $query): array
    {
        $now = ($this->clock)();
        [$f, $key] = self::parseQuery($query, $now);
        $res = $this->compute($uids, $f);
        $hasData = $res['requests'] > 0 || $this->hasData($uids);

        $headline = ['kind' => 'empty', 'total_tokens' => $res['tokens']['total'], 'top_model' => null, 'top_share' => null, 'has_data' => $hasData];
        if ($res['requests'] > 0 && $res['models'] !== []) {
            $top = $res['models'][0];
            foreach ($res['models'] as $m) {
                if ($m['tokens'] > $top['tokens']) {
                    $top = $m;
                }
            }
            $total = $res['tokens']['total'];
            $headline['kind'] = 'total';
            $headline['top_model'] = $top['model'];
            $headline['top_share'] = $total > 0 ? $top['tokens'] / (float) $total : 0.0;
        }
        $range = ['key' => $key, 'from' => $f['from'] === null ? null : Time::isoSec($f['from']), 'to' => Time::isoSec($now)];
        return ['range' => $range] + $res + ['headline' => $headline];
    }

    /**
     * Liest range, tz und höchstens einen Filter (wie parseQuery im Go-Server). from ist die lokale Mitternacht von
     * „heute − (N−1) Tage“ in tz, to bleibt null. Werte, die keine Texte sind (model[]=…), gelten als nicht gesetzt.
     *
     * @param array<string,mixed> $query
     * @return array{0: array<string,mixed>, 1: string} Filter und Zeitraum-Schlüssel
     */
    public static function parseQuery(array $query, int $now): array
    {
        $get = static fn(string $k): ?string => is_string($query[$k] ?? null) ? $query[$k] : null;
        $f = self::NO_FILTER;

        $key = $get('range') ?? '30d';
        if (!array_key_exists($key, self::RANGE_DAYS)) {
            throw new ParamError('range', 'Zeitraum muss 7d, 30d oder all sein');
        }
        $days = self::RANGE_DAYS[$key];

        $f['tz'] = $get('tz') ?? 'UTC';
        // Nur Regionsnamen (mit /) und UTC: Abkürzungen wie CET deuten Zeitzonen-Bibliotheken verschieden.
        if (preg_match(self::TZ_PATTERN, $f['tz']) !== 1 || ($f['tz'] !== 'UTC' && !str_contains($f['tz'], '/'))) {
            throw new ParamError('tz', 'Zeitzone ungültig');
        }
        $zone = self::zone($f['tz']) ?? throw new ParamError('tz', 'Zeitzone unbekannt');

        $n = 0;
        if (($v = $get('model')) !== null) {
            $n++;
            if (preg_match(Limits::MODEL_PATTERN, $v) !== 1) {
                throw new ParamError('model', 'Modellname ungültig');
            }
            $f['model'] = $v;
        }
        if (($v = $get('account')) !== null) {
            $n++;
            if (preg_match(Limits::ID_PATTERN, $v) !== 1) {
                throw new ParamError('account', 'Konto-ID ungültig');
            }
            $f['account'] = $v;
        }
        if (($v = $get('unknown_account')) !== null) {
            $n++;
            if ($v !== '1') {
                throw new ParamError('unknown_account', 'unknown_account darf nur 1 sein');
            }
            $f['unknown_account'] = true;
        }
        if (($v = $get('device')) !== null) {
            $n++;
            $id = Parse::positiveInt($v) ?? throw new ParamError('device', 'Geräte-ID muss eine positive Ganzzahl sein');
            $f['device'] = $id;
        }
        if ($n > 1) {
            throw new ParamError('filter', 'Höchstens ein Filter (model, account, unknown_account, device) ist erlaubt');
        }

        if ($days > 0) {
            $today = (new DateTimeImmutable('@' . $now))->setTimezone($zone)->format('Y-m-d');
            $first = (new DateTimeImmutable($today, new DateTimeZone('UTC')))->modify('-' . ($days - 1) . ' days')->format('Y-m-d');
            $f['from'] = (new DateTimeImmutable($first . ' 00:00:00', $zone))->getTimestamp();
        }
        return [$f, $key];
    }

    /**
     * Zeitzone nur, wenn PHP den Namen genau so kennt (einschließlich Altnamen); sonst null. PHP nähme auch
     * „europe/berlin“ oder Abkürzungen an, die Go und PostgreSQL anders deuten.
     */
    public static function zone(string $tz): ?DateTimeZone
    {
        self::$zones ??= array_flip(DateTimeZone::listIdentifiers(DateTimeZone::ALL_WITH_BC));
        if (!isset(self::$zones[$tz])) {
            return null;
        }
        try {
            return new DateTimeZone($tz);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Alle Kennzahlen der Nutzer für den Filter, in den JSON-Feldern von GET /api/stats (ohne range und headline).
     * Jede Abfrage ist an die Nutzer gebunden; alle laufen in einer Lese-Transaktion (ein Stand der Daten).
     *
     * @param list<int> $uids
     * @param array<string,mixed> $filter Teilfeld von NO_FILTER
     * @return array<string,mixed>
     */
    public function compute(array $uids, array $filter): array
    {
        $f = $filter + self::NO_FILTER;
        $zone = $f['tz'] === '' ? new DateTimeZone('UTC') : self::zone((string) $f['tz']);
        if ($zone === null) {
            throw new ParamError('tz', 'Zeitzone unbekannt');
        }
        // Lesetransaktion (BEGIN): alle Teilabfragen sehen denselben Stand.
        return $this->db->tx(fn(PDO $pdo): array => $this->computeIn($pdo, array_values($uids), $f, $zone), false);
    }

    /**
     * @param list<int> $uids
     * @param array<string,mixed> $f
     * @return array<string,mixed>
     */
    private function computeIn(PDO $pdo, array $uids, array $f, DateTimeZone $zone): array
    {
        [$uc, $ua] = self::userCond('r.user_id', $uids);
        [$fc, $fa] = self::filterConds($f);
        $cond = implode(' and ', array_merge([$uc], $fc));
        $args = array_merge($ua, $fa);
        // Mehrere Nutzer können dieselbe Sitzungskennung haben.
        $session = count($uids) === 1 ? 'r.session_id' : "r.user_id || ':' || r.session_id";

        $row = Sql::run($pdo, "select count(*) as n, count(distinct $session) as s,
                coalesce(sum(r.input), 0) as i, coalesce(sum(r.output), 0) as o,
                coalesce(sum(r.cache_create), 0) as cc, coalesce(sum(r.cache_read), 0) as cr,
                coalesce(sum(r.thinking), 0) as th, coalesce(sum(case when r.subagent then 1 else 0 end), 0) as sub,
                min(r.ts) as first, max(r.ts) as last
              from requests r where $cond", $args)->fetch(PDO::FETCH_ASSOC);
        $n = (int) $row['n'];
        [$in, $out, $cc, $cr] = [(int) $row['i'], (int) $row['o'], (int) $row['cc'], (int) $row['cr']];
        $res = [
            'requests' => $n,
            'sessions' => (int) $row['s'],
            'tokens' => ['input' => $in, 'output' => $out, 'cache_create' => $cc, 'cache_read' => $cr, 'total' => $in + $out + $cc + $cr],
            'active_days' => 0,
            'longest_streak' => 0,
            'record_day' => null,
            'longest_session_sec' => 0,
            'first_activity' => $n > 0 ? Time::isoMs((int) $row['first']) : null,
            'last_activity' => $n > 0 ? Time::isoMs((int) $row['last']) : null,
            'models' => [],
            'daily' => [],
            'legacy' => null,
            'clock' => array_fill(0, 24, 0),
            'week' => array_fill(0, 7, 0),
            'cache_ratio' => self::ratio($cr, $in + $cc + $cr),
            'subagent_share' => self::ratio((int) $row['sub'], $n),
            'thinking_share' => self::ratio((int) $row['th'], $out),
            'longest_answer' => null,
            'tools' => [],
            'badges' => [],
        ];

        if ($n > 0) {
            // Längste Sitzung in Sekunden, gerundet wie numeric::bigint in PostgreSQL.
            $ms = (int) Sql::run($pdo, "select coalesce(max(d), 0) from (
                    select max(r.ts) - min(r.ts) as d from requests r where $cond group by r.user_id, r.session_id)", $args)->fetchColumn();
            $res['longest_session_sec'] = intdiv($ms + 500, 1000);

            foreach (Sql::run($pdo, 'select r.model, sum(' . self::TOKENS . ") as t, count(*) as n
                    from requests r where $cond group by r.model order by t desc, r.model", $args) as $m) {
                $res['models'][] = ['model' => $m['model'], 'tokens' => (int) $m['t'], 'requests' => (int) $m['n']];
            }

            // Muster der Person: lokale Tage der Arbeit.
            $workDays = self::days(Sql::run($pdo, 'select ' . self::LOCAL_DAY . ' as d, sum(' . self::TOKENS . ") as t, count(*) as n
                    from requests r where $cond group by d order by d", $args));
            $res['active_days'] = count($workDays);
            $res['longest_streak'] = self::longestStreak($workDays);
            foreach ($workDays as $d) {
                if ($res['record_day'] === null || $d['tokens'] > $res['record_day']['tokens']) {
                    $res['record_day'] = $d;
                }
            }

            // Tagesreihe in der Zeitzone des Betrachters: Abschnitte gleichen Versatzes als Tabelle z.
            $segments = self::segments($zone, (int) $row['first'], (int) $row['last']);
            $values = implode(', ', array_fill(0, count($segments), '(?, ?, ?)'));
            $res['daily'] = self::days(Sql::run($pdo, "with z(s, e, o) as (values $values)
                    select date(r.ts / 1000 + z.o, 'unixepoch') as d, sum(" . self::TOKENS . ") as t, count(*) as n
                      from requests r join z on r.ts >= z.s and r.ts < z.e
                     where $cond group by d order by d", array_merge(array_merge(...$segments), $args)));

            foreach (Sql::run($pdo, "select cast(strftime('%H', " . self::LOCAL_SEC . ", 'unixepoch') as integer) as h, count(*) as n
                    from requests r where $cond group by h", $args) as $b) {
                $res['clock'][(int) $b['h']] = (int) $b['n'];
            }
            // %w: 0 = Sonntag; week[0] ist Montag.
            foreach (Sql::run($pdo, "select cast(strftime('%w', " . self::LOCAL_SEC . ", 'unixepoch') as integer) as w, count(*) as n
                    from requests r where $cond group by w", $args) as $b) {
                $res['week'][((int) $b['w'] + 6) % 7] = (int) $b['n'];
            }

            $a = Sql::run($pdo, 'select ' . self::LOCAL_DAY . " as d, coalesce(r.output, 0) as o
                    from requests r where $cond order by o desc, r.ts limit 1", $args)->fetch(PDO::FETCH_ASSOC);
            // Die Anfragenzahl der längsten Antwort gehört nicht in die Antwort.
            $res['longest_answer'] = ['date' => $a['d'], 'tokens' => (int) $a['o']];

            foreach (Sql::run($pdo, "select t.tool, sum(t.count) as c
                    from requests r
                    join request_tools t on t.user_id = r.user_id and t.message_id = r.message_id and t.request_id = r.request_id
                   where $cond group by t.tool order by c desc, t.tool limit 10", $args) as $t) {
                $res['tools'][] = ['tool' => $t['tool'], 'count' => (int) $t['c']];
            }
        }

        $res['legacy'] = self::legacy($pdo, $uids, $f, $zone);
        $res['badges'] = self::badges($res);
        return $res;
    }

    /**
     * Altbestand, nur gekennzeichnet und nur für (Gerät, lokaler Tag) ohne jede Anfrage dieses Geräts.
     * Ein Konto-Filter blendet ihn aus (der Altbestand kennt keine Konten).
     *
     * @param list<int> $uids
     * @param array<string,mixed> $f
     * @return array<string,mixed>|null
     */
    private static function legacy(PDO $pdo, array $uids, array $f, DateTimeZone $zone): ?array
    {
        if ($f['account'] !== '') {
            return null;
        }
        [$from, $to] = self::dateRange($f, $zone);
        [$uc, $args] = self::userCond('l.user_id', $uids);
        $conds = [$uc];
        if ($f['model'] !== '') {
            $conds[] = 'l.model = ?';
            $args[] = $f['model'];
        }
        if ($f['device'] !== 0) {
            $conds[] = 'l.device_id = ?';
            $args[] = $f['device'];
        }
        if ($from !== null) {
            $conds[] = 'l.date >= ?';
            $args[] = $from;
        }
        if ($to !== null) {
            $conds[] = 'l.date < ?';
            $args[] = $to;
        }
        // Das Zeitfenster um den Tag (−2 bis +3 Tage UTC) lässt den Index (user_id, ts) greifen.
        $days = self::days(Sql::run($pdo, 'select l.date as d, coalesce(sum(l.tokens), 0) as t, 0 as n
              from legacy_model_days l
             where ' . implode(' and ', $conds) . " and not exists (
                   select 1 from requests r
                    where r.user_id = l.user_id and r.device_id = l.device_id
                      and r.ts >= (cast(strftime('%s', l.date) as integer) - 2 * 86400) * 1000
                      and r.ts < (cast(strftime('%s', l.date) as integer) + 3 * 86400) * 1000
                      and " . self::LOCAL_DAY . ' = l.date)
             group by l.date order by l.date', $args));
        if ($days === []) {
            return null;
        }
        $tokens = 0;
        foreach ($days as $d) {
            $tokens += $d['tokens'];
        }
        return ['days' => count($days), 'first' => $days[0]['date'], 'last' => $days[count($days) - 1]['date'], 'tokens' => $tokens, 'daily' => $days];
    }

    /**
     * from/to als lokale Tage der Zeitzone: von (inklusive) und bis (exklusiv); null = offen.
     * Reicht to in einen Tag hinein, gehört der Tag noch (teilweise) dazu.
     *
     * @param array<string,mixed> $f
     * @return array{0: ?string, 1: ?string}
     */
    private static function dateRange(array $f, DateTimeZone $zone): array
    {
        $from = $f['from'] === null ? null : (new DateTimeImmutable('@' . $f['from']))->setTimezone($zone)->format('Y-m-d');
        $to = null;
        if ($f['to'] !== null) {
            $l = (new DateTimeImmutable('@' . $f['to']))->setTimezone($zone);
            $to = $l->format('Y-m-d');
            if ($l->format('His') !== '000000') {
                $to = (new DateTimeImmutable($to, new DateTimeZone('UTC')))->modify('+1 day')->format('Y-m-d');
            }
        }
        return [$from, $to];
    }

    /**
     * Abschnitte gleichen Versatzes der Zone, die den Zeitraum [first, last] (Millisekunden) abdecken:
     * [von ms, bis ms exklusiv, Versatz in Sekunden]; der erste beginnt offen, der letzte endet offen.
     *
     * @return list<array{int,int,int}>
     */
    private static function segments(DateTimeZone $zone, int $firstMs, int $lastMs): array
    {
        $tr = $zone->getTransitions(intdiv($firstMs, 1000) - 1, intdiv($lastMs, 1000) + 1);
        if ($tr === false || $tr === []) {
            return [[PHP_INT_MIN, PHP_INT_MAX, $zone->getOffset(new DateTimeImmutable('@' . intdiv($firstMs, 1000)))]];
        }
        $tr = array_values($tr);
        $out = [];
        foreach ($tr as $i => $t) {
            $out[] = [
                $i === 0 ? PHP_INT_MIN : $t['ts'] * 1000,
                isset($tr[$i + 1]) ? $tr[$i + 1]['ts'] * 1000 : PHP_INT_MAX,
                (int) $t['offset'],
            ];
        }
        return $out;
    }

    /** @param list<int> $uids */
    private function hasData(array $uids): bool
    {
        [$uc, $ua] = self::userCond('user_id', $uids);
        return (bool) Sql::run($this->db->pdo(), "select exists(select 1 from requests where $uc)
            or exists(select 1 from legacy_model_days where $uc)", array_merge($ua, $ua))->fetchColumn();
    }

    /**
     * Die vier festen Abzeichen aus dem Ergebnis.
     *
     * @param array<string,mixed> $r
     * @return list<array{id:string,value:int}>
     */
    private static function badges(array $r): array
    {
        $out = [];
        if ($r['requests'] === 0) {
            return $out;
        }
        $night = array_sum(array_slice($r['clock'], 0, 5));
        if ($night * 5 >= $r['requests']) { // >= 20 %
            $out[] = ['id' => 'night_owl', 'value' => $night];
        }
        $weekend = $r['week'][5] + $r['week'][6];
        if ($weekend * 5 >= $r['requests'] * 2) { // >= 40 %
            $out[] = ['id' => 'weekend', 'value' => $weekend];
        }
        if ($r['longest_streak'] >= 3) {
            $out[] = ['id' => 'streak', 'value' => $r['longest_streak']];
        }
        if ($r['record_day'] !== null && $r['record_day']['tokens'] >= 1_000_000_000) {
            $out[] = ['id' => 'billion_day', 'value' => $r['record_day']['tokens']];
        }
        return $out;
    }

    /**
     * Längste Folge aufeinanderfolgender Tage in der nach Datum sortierten Liste.
     *
     * @param list<array{date:string}> $days
     */
    private static function longestStreak(array $days): int
    {
        $best = 0;
        $cur = 0;
        $prev = null;
        foreach ($days as $d) {
            $t = DateTimeImmutable::createFromFormat('!Y-m-d', $d['date'], new DateTimeZone('UTC'));
            if ($t === false) {
                continue;
            }
            $day = intdiv($t->getTimestamp(), 86400);
            $cur = $cur > 0 && $prev !== null && $day === $prev + 1 ? $cur + 1 : 1;
            $prev = $day;
            $best = max($best, $cur);
        }
        return $best;
    }

    /** @return list<array{date:string,tokens:int,requests:int}> */
    private static function days(PDOStatement $st): array
    {
        $out = [];
        foreach ($st as $row) {
            $out[] = ['date' => (string) $row['d'], 'tokens' => (int) $row['t'], 'requests' => (int) $row['n']];
        }
        return $out;
    }

    private static function ratio(int $num, int $den): ?float
    {
        return $den === 0 ? null : $num / (float) $den;
    }

    /**
     * Bedingungen des Filters auf requests (Alias r) ohne die Nutzerbedingung; Werte nur als Parameter.
     *
     * @param array<string,mixed> $f
     * @return array{0: list<string>, 1: list<int|string>}
     */
    public static function filterConds(array $f): array
    {
        $f += self::NO_FILTER;
        $conds = [];
        $args = [];
        if ($f['model'] !== '') {
            $conds[] = 'r.model = ?';
            $args[] = (string) $f['model'];
        }
        if ($f['account'] !== '') {
            $conds[] = 'r.account_id = ?';
            $args[] = (string) $f['account'];
        }
        if ($f['unknown_account']) {
            $conds[] = 'r.account_id is null';
        }
        if ($f['device'] !== 0) {
            $conds[] = 'r.device_id = ?';
            $args[] = (int) $f['device'];
        }
        if ($f['from'] !== null) {
            $conds[] = 'r.ts >= ?';
            $args[] = (int) $f['from'] * 1000;
        }
        if ($f['to'] !== null) {
            $conds[] = 'r.ts < ?';
            $args[] = (int) $f['to'] * 1000;
        }
        return [$conds, $args];
    }

    /**
     * @param list<int> $uids
     * @return array{0: string, 1: list<int>}
     */
    private static function userCond(string $column, array $uids): array
    {
        if ($uids === []) {
            return ['0', []];
        }
        if (count($uids) === 1) {
            return [$column . ' = ?', [(int) $uids[0]]];
        }
        return [$column . ' in (' . implode(', ', array_fill(0, count($uids), '?')) . ')', array_map('intval', $uids)];
    }
}
