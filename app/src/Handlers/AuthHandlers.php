<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Auth\AuthError;
use Tokenlore\Auth\Sessions;
use Tokenlore\Auth\Users;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Http\SessionCookie;

// Anmeldung, Abmeldung, eigenes Konto, Passwortwechsel und Widerruf anderer Sitzungen; Verhalten, Status
// und Texte wie internal/httpapi/auth_handlers.go und account_handlers.go. Die Grenze je IP für Login und
// Passwortwechsel ist limitIp('login'); eine Grenze gleichzeitiger Anmeldungen (MaxLogins) gibt es nicht.
final class AuthHandlers
{
    private readonly Closure $clock;

    /** @param callable(): int $clock Unix-Sekunden */
    private function __construct(private readonly Sessions $sessions, private readonly Users $users, callable $clock, private readonly Audit $audit)
    {
        $this->clock = Closure::fromCallable($clock);
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time()); dieselbe Uhr wie die Middleware
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     */
    public static function register(Router $router, Middleware $mw, Sessions $sessions, Users $users, ?callable $clock = null, ?Audit $audit = null): void
    {
        $h = new self($sessions, $users, $clock ?? time(...), $audit ?? new Audit());
        $router->add('POST', '/api/login', Middleware::chain($h->login(...), $mw->limitIp('login'), $mw->jsonOnly(), $mw->maxBody(4096)));
        $router->add('POST', '/api/logout', Middleware::chain($h->logout(...), $mw->requireSession(), $mw->requireCsrf()));
        $router->add('GET', '/api/me', Middleware::chain($h->me(...), $mw->requireSession(), $mw->requireCsrf()));
        // Passwort ändern: Login-Grenze wie die Anmeldung (Argon2id, Fehlversuche zählen).
        $router->add('POST', '/api/password', Middleware::chain(
            $h->changePassword(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->limitIp('login'),
            $mw->jsonOnly(),
            $mw->maxBody(4096),
        ));
        $router->add('POST', '/api/sessions/revoke-others', Middleware::chain($h->revokeOthers(...), $mw->requireSession(), $mw->requireCsrf()));
    }

    private function login(Request $r): Response
    {
        $req = StrictJson::strings($r->body, ['username', 'password']);
        if ($req === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        try {
            $s = $this->sessions->login($req['username'], $req['password'], ($this->clock)());
        } catch (AuthError $e) {
            // Nutzer-ID null: unbekannter Benutzername (der Name selbst wird nie protokolliert).
            return match ($e->reason) {
                AuthError::LOCKED => $this->audited($r, 'login_gesperrt', $e->uid, Response::error(423, 'Konto vorübergehend gesperrt')),
                AuthError::BAD_CREDENTIALS => $this->audited($r, 'login_fehlgeschlagen', $e->uid, Response::error(401, 'Anmeldung fehlgeschlagen')),
                default => throw $e,
            };
        }
        $this->audit->request($r, 'login_ok', $s['uid']);
        return SessionCookie::set(Response::empty(), $r, $s['token'], Sessions::TTL);
    }

    private function logout(Request $r): Response
    {
        $token = SessionCookie::token($r);
        if ($token !== null) {
            $this->sessions->logout($token);
        }
        $this->audit->request($r, 'logout', (int) $r->attr('uid'));
        return SessionCookie::set(Response::empty(), $r, '', 0);
    }

    /** @param array<string,int|string> $fields */
    private function audited(Request $r, string $event, ?int $uid, Response $response, array $fields = []): Response
    {
        $this->audit->request($r, $event, $uid, $fields);
        return $response;
    }

    private function me(Request $r): Response
    {
        $user = $this->users->byId((int) $r->attr('uid'));
        if ($user === null) {
            return Response::error(401, 'Nicht angemeldet');
        }
        // Schlüssel alphabetisch wie die Go-Antwort (map), ergänzt um die Rolle.
        return Response::json(200, ['csrf_token' => (string) $r->attr('csrf'), 'role' => $user['role'], 'username' => $user['username']]);
    }

    /**
     * Ein falsches aktuelles Passwort zählt wie ein Fehlversuch bei der Anmeldung; während einer Sperre
     * wird es nicht geprüft (kein Passwort-Orakel).
     */
    private function changePassword(Request $r): Response
    {
        $req = StrictJson::strings($r->body, ['current', 'new']);
        if ($req === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        $token = SessionCookie::token($r);
        if ($token === null) {
            return Response::error(401, 'Nicht angemeldet');
        }
        $uid = (int) $r->attr('uid');
        $way = ['weg' => 'passwort_aendern'];
        try {
            $this->sessions->changePassword($uid, $req['current'], $req['new'], Sessions::hashToken($token), ($this->clock)());
        } catch (AuthError $e) {
            return match ($e->reason) {
                // path "new": die Webseite zeigt den Fehler am Feld „Neues Passwort“.
                AuthError::PASSWORD_TOO_SHORT => Response::json(400, ['error' => $e->getMessage(), 'path' => 'new']),
                AuthError::LOCKED => $this->audited($r, 'login_gesperrt', $uid, Response::error(423, 'Konto vorübergehend gesperrt'), $way),
                AuthError::BAD_CREDENTIALS => $this->audited($r, 'login_fehlgeschlagen', $uid, Response::error(403, 'Aktuelles Passwort falsch'), $way),
                default => throw $e,
            };
        }
        $this->audit->request($r, 'passwort_geaendert', $uid);
        return Response::empty();
    }

    private function revokeOthers(Request $r): Response
    {
        $token = SessionCookie::token($r);
        if ($token === null) {
            return Response::error(401, 'Nicht angemeldet');
        }
        $n = $this->sessions->revoke((int) $r->attr('uid'), Sessions::hashToken($token));
        $this->audit->request($r, 'sitzungen_widerrufen', (int) $r->attr('uid'), ['anzahl' => $n]);
        return Response::json(200, ['revoked' => $n]);
    }
}
