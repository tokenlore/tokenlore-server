<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Auth\AuthError;
use Tokenlore\Auth\Sessions;
use Tokenlore\Auth\Users;
use Tokenlore\Config\BaseUrl;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Config\SettingError;
use Tokenlore\Db\Database;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Stats\ParamError;
use Tokenlore\Stats\Stats;
use Tokenlore\Team\LastAdminError;
use Tokenlore\Team\Members;

// Routen für Admins unter /api/admin/: Mitglieder verwalten, Team-Statistik und Server-Einstellungen.
// Alle laufen über requireSession, requireCsrf und requireAdmin. Die Rolle kommt aus der Sitzungsprüfung, die
// sie bei jeder Anfrage frisch aus der Tabelle users liest (Auth\Sessions::user): wem die Rechte entzogen
// werden, der verliert sie mit der nächsten Anfrage, ohne dass seine Sitzung enden muss.
final class AdminHandlers
{
    /** JSON-Rümpfe der Verwaltung. */
    private const MAX_BODY = 4096;
    /** PUT /api/admin/server: Zertifikat bis 64 KiB plus JSON-Hülle und maskierte Zeilenumbrüche. */
    private const MAX_SERVER_BODY = 64 * 1024 + 4096;
    /** Positive ID ohne führende Null, höchstens 16 Stellen (passt in int). */
    private const ID_PATTERN = '/^[1-9][0-9]{0,15}\z/';

    private readonly Closure $clock;
    private readonly Closure $extensionLoaded;
    private readonly Members $members;

    /**
     * @param callable(): int $clock
     * @param callable(string): bool $extensionLoaded
     */
    private function __construct(
        private readonly Database $db,
        private readonly Sessions $sessions,
        private readonly Users $users,
        private readonly ServerSettings $settings,
        callable $clock,
        private readonly Audit $audit,
        callable $extensionLoaded,
    ) {
        $this->clock = Closure::fromCallable($clock);
        $this->extensionLoaded = Closure::fromCallable($extensionLoaded);
        $this->members = new Members($db);
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time()); dieselbe Uhr wie die Middleware
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log); jede gelungene Änderung, nur mit IDs
     * @param (callable(string): bool)|null $extensionLoaded Prüfung auf PHP-Erweiterungen (Standard: extension_loaded; Tests)
     */
    public static function register(
        Router $router,
        Middleware $mw,
        Database $db,
        Sessions $sessions,
        Users $users,
        ServerSettings $settings,
        ?callable $clock = null,
        ?Audit $audit = null,
        ?callable $extensionLoaded = null,
    ): void {
        $h = new self($db, $sessions, $users, $settings, $clock ?? time(...), $audit ?? new Audit(), $extensionLoaded ?? extension_loaded(...));
        $admin = static fn(callable $handler, callable ...$more): callable
            => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf(), $mw->requireAdmin(), ...$more);
        $json = [$mw->jsonOnly(), $mw->maxBody(self::MAX_BODY)];
        // Aktionen ohne Rumpf: kein Content-Type nötig, ein Rumpf wird nicht gelesen.
        $empty = [$mw->maxBody(self::MAX_BODY)];

        $router->add('GET', '/api/admin/users', $admin($h->listUsers(...)));
        $router->add('POST', '/api/admin/users', $admin($h->createUser(...), ...$json));
        $router->add('PUT', '/api/admin/users/{id}/role', $admin($h->setRole(...), ...$json));
        $router->add('POST', '/api/admin/users/{id}/password', $admin($h->setPassword(...), ...$json));
        $router->add('POST', '/api/admin/users/{id}/revoke-sessions', $admin($h->revokeSessions(...), ...$empty));
        $router->add('POST', '/api/admin/users/{id}/disable', $admin($h->disable(...), ...$empty));
        $router->add('POST', '/api/admin/users/{id}/enable', $admin($h->enable(...), ...$empty));
        $router->add('GET', '/api/admin/server', $admin($h->getServer(...)));
        $router->add('PUT', '/api/admin/server', $admin($h->putServer(...), $mw->jsonOnly(), $mw->maxBody(self::MAX_SERVER_BODY)));
        $router->add('GET', '/api/admin/team/stats', $admin($h->teamStats(...)));
    }

    private function listUsers(): Response
    {
        return Response::json(200, $this->members->list());
    }

    private function createUser(Request $r): Response
    {
        $req = StrictJson::strings($r->body, ['username', 'password', 'role']);
        if ($req === null) {
            return self::badRequest();
        }
        try {
            $id = $this->users->create($req['username'], $req['password'], $req['role']);
        } catch (AuthError $e) {
            return self::authError($e);
        }
        $this->audited($r, 'admin_konto_angelegt', $id);
        return Response::json(201, ['id' => $id]);
    }

    /** Ereignis einer gelungenen Admin-Aktion: wer (Sitzung), von wo (IP), an welchem Konto; nie Namen oder Passwörter. */
    private function audited(Request $r, string $event, ?int $account): void
    {
        $this->audit->request($r, $event, (int) $r->attr('uid'), $account === null ? [] : ['konto' => $account]);
    }

    private function setRole(Request $r, array $p): Response
    {
        $id = self::id($p);
        if ($id === null) {
            return self::unknownUser();
        }
        $req = StrictJson::strings($r->body, ['role']);
        if ($req === null) {
            return self::badRequest();
        }
        try {
            $this->members->setRole($id, $req['role']);
        } catch (AuthError $e) {
            return self::authError($e);
        } catch (LastAdminError $e) {
            return Response::error(409, $e->getMessage());
        }
        $this->audited($r, 'admin_rolle', $id);
        return Response::empty();
    }

    /** Neues Passwort; hebt die Sperre nach Fehlversuchen auf und beendet alle Sitzungen des Kontos. */
    private function setPassword(Request $r, array $p): Response
    {
        $id = self::id($p);
        if ($id === null) {
            return self::unknownUser();
        }
        $req = StrictJson::strings($r->body, ['password']);
        if ($req === null) {
            return self::badRequest();
        }
        try {
            $this->users->resetPassword($id, $req['password']);
        } catch (AuthError $e) {
            return self::authError($e);
        }
        $this->audited($r, 'admin_passwort', $id);
        return Response::empty();
    }

    private function revokeSessions(Request $r, array $p): Response
    {
        $id = self::id($p);
        if ($id === null || !$this->members->exists($id)) {
            return self::unknownUser();
        }
        $this->sessions->revoke($id, null);
        $this->audited($r, 'admin_sitzungen_beendet', $id);
        return Response::empty();
    }

    private function disable(Request $r, array $p): Response
    {
        $id = self::id($p);
        if ($id === null) {
            return self::unknownUser();
        }
        try {
            $this->members->disable($id, ($this->clock)());
        } catch (AuthError $e) {
            return self::authError($e);
        } catch (LastAdminError $e) {
            return Response::error(409, $e->getMessage());
        }
        $this->audited($r, 'admin_gesperrt', $id);
        return Response::empty();
    }

    private function enable(Request $r, array $p): Response
    {
        $id = self::id($p);
        if ($id === null) {
            return self::unknownUser();
        }
        try {
            $this->users->enable($id);
        } catch (AuthError $e) {
            return self::authError($e);
        }
        $this->audited($r, 'admin_entsperrt', $id);
        return Response::empty();
    }

    private function getServer(Request $r): Response
    {
        $fp = $this->settings->caFingerprint();
        return Response::json(200, [
            'public_url' => $this->settings->publicUrl(),
            'detected_url' => BaseUrl::detect($r, $this->settings->trustProxy()),
            'trust_proxy' => $this->settings->trustProxy(),
            'ca_fingerprint' => $fp === '' ? null : $fp,
            // Ohne Sodium prüft der Server keine Signaturen der Plugins; die Seite zeigt dann die Anleitung.
            'sodium' => ($this->extensionLoaded)('sodium'),
        ]);
    }

    /**
     * Ändert nur die genannten Felder, alles oder nichts. public_url und ca_pem: "" oder null entfernt den Wert.
     * Fehler: 400 mit path. Unbekannte Felder lehnt der Handler ab; Typen und Werte prüft ServerSettings::save,
     * seine Ausnahme nennt das betroffene Feld.
     */
    private function putServer(Request $r): Response
    {
        try {
            $data = json_decode($r->body, false, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::badRequest();
        }
        if (!$data instanceof \stdClass) {
            return self::badRequest();
        }
        $changes = get_object_vars($data);
        if (array_diff(array_keys($changes), ['public_url', 'trust_proxy', 'ca_pem']) !== []) {
            return self::badRequest();
        }
        try {
            $this->settings->save($changes);
        } catch (SettingError $e) {
            return self::invalid($e->getMessage(), $e->field);
        }
        // Ohne die Werte: Adresse und Zertifikat gehören nicht ins Protokoll.
        $this->audited($r, 'server_einstellungen', null);
        return Response::empty();
    }

    /**
     * Statistik eines Kontos (user=<id>) oder die Summe aller Konten (user=all), gleiche Form und Parameter
     * wie GET /api/stats.
     */
    private function teamStats(Request $r): Response
    {
        $user = $r->query['user'] ?? null;
        if ($user === 'all') {
            $uids = $this->members->ids();
        } elseif (is_string($user) && preg_match(self::ID_PATTERN, $user) === 1) {
            if (!$this->members->exists((int) $user)) {
                return self::unknownUser();
            }
            $uids = [(int) $user];
        } else {
            return self::invalid('user muss all oder eine Nutzer-ID sein', 'user');
        }
        $query = $r->query;
        unset($query['user']);
        try {
            return Response::json(200, (new Stats($this->db, $this->clock))->forUsers($uids, $query));
        } catch (ParamError $e) {
            return StatsHandlers::paramError($e);
        }
    }

    /** @param array<string,string> $p */
    private static function id(array $p): ?int
    {
        $raw = $p['id'] ?? '';
        return preg_match(self::ID_PATTERN, $raw) === 1 ? (int) $raw : null;
    }

    private static function authError(AuthError $e): Response
    {
        return match ($e->reason) {
            AuthError::INVALID_USERNAME => self::invalid($e->getMessage(), 'username'),
            AuthError::PASSWORD_TOO_SHORT => self::invalid($e->getMessage(), 'password'),
            AuthError::INVALID_ROLE => self::invalid($e->getMessage(), 'role'),
            AuthError::USERNAME_TAKEN => Response::error(409, $e->getMessage()),
            AuthError::UNKNOWN_USER => self::unknownUser(),
            default => throw $e,
        };
    }

    private static function invalid(string $msg, string $path): Response
    {
        return Response::json(400, ['error' => $msg, 'path' => $path]);
    }

    private static function badRequest(): Response
    {
        return Response::error(400, 'Ungültige Anfrage');
    }

    private static function unknownUser(): Response
    {
        return Response::error(404, AuthError::of(AuthError::UNKNOWN_USER)->getMessage());
    }
}
