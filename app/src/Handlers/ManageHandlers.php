<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Tokenlore\Audit;
use PDO;
use Tokenlore\Accounts\AccountError;
use Tokenlore\Accounts\Accounts;
use Tokenlore\Db\Database;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Protocol\Limits;
use Tokenlore\Util\Names;
use Tokenlore\Util\Sql;

// Routen der Verwaltung (wie manage_handlers.go, settings_handlers.go und privacy_handlers.go): Kontonamen,
// Einstellungen und der Beispiel-Datensatz der Datenschutzseite. Alle mit Sitzung und CSRF-Prüfung.
// Änderungen landen wie im Go-Server im Sicherheitsprotokoll (nur IDs und Anzahlen, keine Namen).
final class ManageHandlers
{
    /** Grenzen der Plausibilitäts-Schwellen (Anfragen je Sekunde bzw. Minute). */
    private const MAX_FLAG_PER_SECOND = 10_000;
    private const MAX_FLAG_PER_MINUTE = 100_000;
    /** Standardwerte der Tabelle settings, falls die Zeile fehlt. */
    private const DEFAULT_SETTINGS = ['flag_per_second' => 50, 'flag_per_minute' => 500];

    private function __construct(private readonly Database $db, private readonly Audit $audit)
    {
    }

    /** @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log) */
    public static function register(Router $router, Middleware $mw, Database $db, ?Audit $audit = null): void
    {
        $h = new self($db, $audit ?? new Audit());
        $sess = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf());
        $json = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf(), $mw->jsonOnly(), $mw->maxBody(4096));
        $router->add('PUT', '/api/accounts/{id}/name', $json($h->renameAccount(...)));
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
     * Die jüngste gespeicherte Anfrage des Nutzers als signierte Zeile (Hülle z/s, z Byte für Byte wie geliefert) und
     * ihre Sitzung, genau in den JSON-Feldern, in denen das Plugin sie sendet (Abschnitte „Hülle“ und „Session“ in
     * protocol/doc.md). Ohne Daten {"request":null,"session":null}.
     */
    private function privacyExample(Request $r): Response
    {
        $uid = (int) $r->attr('uid');
        $pdo = $this->db->pdo();
        $q = Sql::run($pdo, 'select z, s, session_id from requests where user_id = ?
              order by ts desc, message_id desc, request_id desc limit 1', [$uid])->fetch(PDO::FETCH_ASSOC);
        if ($q === false) {
            return Response::json(200, ['request' => null, 'session' => null]);
        }
        $req = ['z' => (string) $q['z'], 's' => (string) $q['s']];
        $out = ['request' => $req, 'session' => null];
        $s = Sql::run($pdo, "select session_id, coalesce(cc_version, '') as cc_version,
                coalesce(account_id, '') as account_id from sessions where user_id = ? and session_id = ?", [$uid, $q['session_id']])
            ->fetch(PDO::FETCH_ASSOC);
        if ($s !== false) {
            $out['session'] = ['session_id' => $s['session_id']];
            foreach (['cc_version', 'account_id'] as $k) {
                if ($s[$k] !== '') {
                    $out['session'][$k] = $s[$k];
                }
            }
        }
        return Response::json(200, $out);
    }
}
