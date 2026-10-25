<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use PDO;
use stdClass;
use Tokenlore\Accounts\AccountError;
use Tokenlore\Accounts\Accounts;
use Tokenlore\Accounts\Assign;
use Tokenlore\Db\Database;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Protocol\Limits;
use Tokenlore\Util\Names;
use Tokenlore\Util\Parse;
use Tokenlore\Util\Sql;
use Tokenlore\Util\Time;

// Routen der Verwaltung (wie manage_handlers.go, settings_handlers.go und privacy_handlers.go): Kontonamen,
// Zuordnungen, Einstellungen und der Beispiel-Datensatz der Datenschutzseite. Alle mit Sitzung und CSRF-Prüfung.
// Änderungen landen wie im Go-Server im Sicherheitsprotokoll (nur IDs und Anzahlen, keine Namen).
final class ManageHandlers
{
    /** Grenzen der Plausibilitäts-Schwellen (Anfragen je Sekunde bzw. Minute). */
    private const MAX_FLAG_PER_SECOND = 10_000;
    private const MAX_FLAG_PER_MINUTE = 100_000;
    /** Standardwerte der Tabelle settings, falls die Zeile fehlt. */
    private const DEFAULT_SETTINGS = ['flag_per_second' => 50, 'flag_per_minute' => 500];

    private function __construct(private readonly Database $db, private readonly Closure $clock, private readonly Audit $audit)
    {
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time())
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     */
    public static function register(Router $router, Middleware $mw, Database $db, ?callable $clock = null, ?Audit $audit = null): void
    {
        $h = new self($db, $clock === null ? time(...) : Closure::fromCallable($clock), $audit ?? new Audit());
        $sess = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf());
        $json = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf(), $mw->jsonOnly(), $mw->maxBody(4096));
        $router->add('PUT', '/api/accounts/{id}/name', $json($h->renameAccount(...)));
        $router->add('POST', '/api/accounts/assign', $json($h->assign(...)));
        $router->add('GET', '/api/accounts/assignments', $sess($h->listAssignments(...)));
        $router->add('POST', '/api/accounts/assignments/{id}/undo', Middleware::chain($h->undo(...), $mw->requireSession(), $mw->requireCsrf(), $mw->maxBody(4096)));
        $router->add('GET', '/api/settings', $sess($h->getSettings(...)));
        $router->add('PUT', '/api/settings', $json($h->putSettings(...)));
        $router->add('GET', '/api/privacy/example', $sess($h->privacyExample(...)));
    }

    /** @param array<string,string> $p */
    private function renameAccount(Request $r, array $p): Response
    {
        [$req] = StrictJson::decode($r->body, ['display_name' => 'string']);
        if ($req === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        $name = $req['display_name'] ?? '';
        if (Names::trimSpace($name) !== '' && Names::clean($name) === null) {
            return Response::error(400, sprintf('Kontoname ungültig (höchstens %d Zeichen, keine Steuer- oder Formatzeichen)', Limits::MAX_DEVICE_NAME));
        }
        $id = $p['id'] ?? '';
        if (preg_match(Limits::ID_PATTERN, $id) !== 1) {
            return Response::error(404, 'Konto nicht gefunden');
        }
        try {
            (new Accounts($this->db))->rename((int) $r->attr('uid'), $id, $name);
        } catch (AccountError $e) {
            return $e->kind === AccountError::NOT_FOUND ? Response::error(404, 'Konto nicht gefunden') : Response::error(400, 'Ungültige Anfrage');
        }
        $this->audit->request($r, 'konto_umbenannt', (int) $r->attr('uid'));
        return Response::empty();
    }

    private function assign(Request $r): Response
    {
        [$req] = StrictJson::decode($r->body, ['device_id' => 'int', 'from' => 'string', 'to' => 'string', 'account_id' => 'string', 'dry_run' => 'bool']);
        if ($req === null || !isset($req['device_id'])) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        $from = $req['from'] ?? '';
        $to = $req['to'] ?? '';
        $account = $req['account_id'] ?? '';
        if (Assign::parseRange($from, $to) === null) {
            return Response::error(400, sprintf('Zeitraum ungültig (JJJJ-MM-TT, ab 2024-01-01, höchstens %d Tage)', Assign::MAX_RANGE_DAYS));
        }
        if (preg_match(Limits::ID_PATTERN, $account) !== 1) {
            return Response::error(400, 'Kontokennung ungültig');
        }
        if ($req['device_id'] <= 0) {
            return Response::error(404, 'Nicht gefunden');
        }
        try {
            [$id, $n] = (new Assign($this->db))->assign((int) $r->attr('uid'), $req['device_id'], $from, $to, $account, $req['dry_run'] ?? false, ($this->clock)());
        } catch (AccountError $e) {
            return $e->kind === AccountError::NOT_FOUND ? Response::error(404, 'Nicht gefunden') : Response::error(400, 'Ungültige Anfrage');
        }
        // Die Vorschau (dry_run) und eine leere Zuordnung legen nichts an und erzeugen kein Ereignis.
        if ($id > 0) {
            $this->audit->request($r, 'konto_zugeordnet', (int) $r->attr('uid'), ['zuordnung' => $id, 'anzahl' => $n]);
        }
        return Response::json(200, ['assignment_id' => $id > 0 ? $id : null, 'requests' => $n]);
    }

    private function listAssignments(Request $r): Response
    {
        return Response::json(200, (new Assign($this->db))->list((int) $r->attr('uid')));
    }

    /** @param array<string,string> $p */
    private function undo(Request $r, array $p): Response
    {
        $id = Parse::positiveInt($p['id'] ?? '');
        if ($id === null) {
            return Response::error(404, 'Zuordnung nicht gefunden');
        }
        try {
            $n = (new Assign($this->db))->undo((int) $r->attr('uid'), $id, ($this->clock)());
        } catch (AccountError) {
            return Response::error(404, 'Zuordnung nicht gefunden');
        }
        $this->audit->request($r, 'zuordnung_rueckgaengig', (int) $r->attr('uid'), ['zuordnung' => $id, 'anzahl' => $n]);
        return Response::json(200, ['requests' => $n]);
    }

    private function getSettings(Request $r): Response
    {
        $row = Sql::run($this->db->pdo(), 'select flag_per_second, flag_per_minute from settings where user_id = ?', [(int) $r->attr('uid')])
            ->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return Response::json(200, self::DEFAULT_SETTINGS);
        }
        return Response::json(200, ['flag_per_second' => (int) $row['flag_per_second'], 'flag_per_minute' => (int) $row['flag_per_minute']]);
    }

    private function putSettings(Request $r): Response
    {
        $fieldError = static fn(string $msg, string $path): Response => Response::json(400, ['error' => $msg, 'path' => $path]);
        [$req, $err, $field] = StrictJson::decode($r->body, ['flag_per_second' => 'int', 'flag_per_minute' => 'int']);
        if ($req === null) {
            return $err === 'type' && $field !== '' ? $fieldError('muss eine ganze Zahl sein', $field) : $fieldError('Ungültige Anfrage', '');
        }
        $perSecond = $req['flag_per_second'] ?? 0;
        $perMinute = $req['flag_per_minute'] ?? 0;
        if ($perSecond < 1 || $perSecond > self::MAX_FLAG_PER_SECOND) {
            return $fieldError('muss zwischen 1 und 10000 liegen', 'flag_per_second');
        }
        if ($perMinute < 1 || $perMinute > self::MAX_FLAG_PER_MINUTE) {
            return $fieldError('muss zwischen 1 und 100000 liegen', 'flag_per_minute');
        }
        // Fehlt die Zeile (sollte beim Anlegen des Nutzers entstehen), wird sie angelegt.
        Sql::run($this->db->pdo(), 'insert into settings (user_id, flag_per_second, flag_per_minute) values (?, ?, ?)
            on conflict (user_id) do update set flag_per_second = excluded.flag_per_second, flag_per_minute = excluded.flag_per_minute',
            [(int) $r->attr('uid'), $perSecond, $perMinute]);
        $this->audit->request($r, 'einstellungen_geaendert', (int) $r->attr('uid'));
        return Response::empty();
    }

    /**
     * Die jüngste gespeicherte Anfrage des Nutzers und ihre Sitzung, genau in den JSON-Feldern, in denen das Plugin
     * sie sendet (protocol.Request und protocol.Session). Ohne Daten {"request":null,"session":null}.
     */
    private function privacyExample(Request $r): Response
    {
        $uid = (int) $r->attr('uid');
        $pdo = $this->db->pdo();
        $q = Sql::run($pdo, "select request_id, message_id, session_id, ts, utc_offset_min, model,
                coalesce(input, 0) as input, coalesce(output, 0) as output, coalesce(cache_create, 0) as cache_create,
                coalesce(cache_read, 0) as cache_read, coalesce(cache_1h, 0) as cache_1h, coalesce(cache_5m, 0) as cache_5m,
                coalesce(thinking, 0) as thinking, coalesce(web_search, 0) as web_search, coalesce(web_fetch, 0) as web_fetch,
                coalesce(stop_reason, '') as stop_reason, coalesce(subagent, 0) as subagent, coalesce(account_id, '') as account_id, extra
              from requests where user_id = ?
              order by ts desc, message_id desc, request_id desc limit 1", [$uid])->fetch(PDO::FETCH_ASSOC);
        if ($q === false) {
            return Response::json(200, ['request' => null, 'session' => null]);
        }
        $req = [
            'request_id' => $q['request_id'], 'message_id' => $q['message_id'], 'session_id' => $q['session_id'],
            'ts' => Time::isoMs((int) $q['ts']), 'utc_offset_min' => (int) $q['utc_offset_min'], 'model' => $q['model'],
        ];
        foreach (['input', 'output', 'cache_create', 'cache_read', 'cache_1h', 'cache_5m', 'thinking', 'web_search', 'web_fetch'] as $k) {
            $req[$k] = (int) $q[$k];
        }
        // Leere Felder mit omitempty fallen weg wie in Go.
        if ($q['stop_reason'] !== '') {
            $req['stop_reason'] = $q['stop_reason'];
        }
        $req['subagent'] = (bool) $q['subagent'];
        $tools = [];
        foreach (Sql::run($pdo, 'select tool, count from request_tools where user_id = ? and message_id = ? and request_id = ?',
            [$uid, $q['message_id'], $q['request_id']]) as $t) {
            $tools[(string) $t['tool']] = (int) $t['count'];
        }
        if ($tools !== []) {
            $req['tools'] = self::sortedObject($tools);
        }
        if ($q['account_id'] !== '') {
            $req['account_id'] = $q['account_id'];
        }
        $extra = $q['extra'] === null ? null : json_decode((string) $q['extra'], true);
        if (is_array($extra) && $extra !== []) {
            $req['extra'] = self::sortedObject($extra);
        }

        $out = ['request' => $req, 'session' => null];
        $s = Sql::run($pdo, "select session_id, coalesce(project_id, '') as project_id, coalesce(cc_version, '') as cc_version,
                coalesce(account_id, '') as account_id from sessions where user_id = ? and session_id = ?", [$uid, $q['session_id']])
            ->fetch(PDO::FETCH_ASSOC);
        if ($s !== false) {
            $out['session'] = ['session_id' => $s['session_id']];
            foreach (['project_id', 'cc_version', 'account_id'] as $k) {
                if ($s[$k] !== '') {
                    $out['session'][$k] = $s[$k];
                }
            }
        }
        return Response::json(200, $out);
    }

    /**
     * JSON-Objekt mit Schlüsseln in Byte-Reihenfolge (wie eine Go-Map); auch Schlüssel wie "0" bleiben ein Objekt.
     *
     * @param array<int|string,mixed> $map
     */
    private static function sortedObject(array $map): stdClass
    {
        ksort($map, SORT_STRING);
        $o = new stdClass();
        foreach ($map as $k => $v) {
            $o->{(string) $k} = $v;
        }
        return $o;
    }
}
