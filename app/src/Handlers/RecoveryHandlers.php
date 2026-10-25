<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Tokenlore\Audit;
use Tokenlore\Auth\AuthError;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Setup\Recovery;
use Tokenlore\Setup\RecoveryBusy;
use Tokenlore\Setup\RecoveryDenied;
use Tokenlore\Team\Members;

// Notfall-Zugang ohne Anmeldung: POST /api/recovery/start und /api/recovery/finish (siehe Setup\Recovery).
// Beide mit einer Grenze je IP (limitIp('recovery'): Rate wie die Anmeldung, aber ein eigener Topf, damit Recovery-Spam
// die Anmeldung nicht sperrt und umgekehrt), die vor jeder Arbeit greift.
// Kein CSRF-Token: es gibt keine Sitzung, und finish verlangt application/json (fremde Seiten können das
// nicht ohne CORS-Vorabfrage senden); der eigentliche Nachweis ist ohnehin die Datei im Datenordner.
// Start, Abschluss und Ablehnung stehen im Sicherheitsprotokoll, nie mit Code, Name oder Passwort.
final class RecoveryHandlers
{
    private function __construct(private readonly Recovery $recovery, private readonly Audit $audit)
    {
    }

    /** @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log) */
    public static function register(Router $router, Middleware $mw, Recovery $recovery, ?Audit $audit = null): void
    {
        $h = new self($recovery, $audit ?? new Audit());
        // start hat keinen Rumpf (die Webseite sendet auch keinen Content-Type).
        $router->add('POST', '/api/recovery/start', Middleware::chain($h->start(...), $mw->limitIp('recovery'), $mw->maxBody(4096)));
        $router->add('POST', '/api/recovery/finish', Middleware::chain($h->finish(...), $mw->limitIp('recovery'), $mw->jsonOnly(), $mw->maxBody(4096)));
    }

    private function start(Request $r): Response
    {
        try {
            $s = $this->recovery->start();
        } catch (RecoveryBusy $e) {
            // Alle Plätze belegt, keiner alt genug: der Code eines Berechtigten wird nicht verdrängt. Bewusst nicht im
            // Sicherheitsprotokoll: Ein verteilter Angreifer (der Fall hier) bestimmte sonst die Zahl der Zeilen, und die
            // Ratengrenze je IP begrenzt nur die einzelne Adresse. Die 429-Antwort selbst zeigt den Zustand.
            return Response::error(429, $e->getMessage())->withHeader('Retry-After', (string) $e->retryAfter);
        }
        $this->audit->request($r, 'notfall_start', null);
        return Response::json(200, ['code' => $s['code'], 'file' => Recovery::FILE, 'expires_at' => Members::iso($s['expires_at'])]);
    }

    private function finish(Request $r): Response
    {
        $req = StrictJson::strings($r->body, ['code', 'username', 'password']);
        if ($req === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        if (trim($req['username']) === '') {
            return Response::json(400, ['error' => 'Benutzername fehlt', 'path' => 'username']);
        }
        try {
            $id = $this->recovery->finish($req['code'], $req['username'], $req['password']);
        } catch (RecoveryDenied $e) {
            $this->audit->request($r, 'notfall_abgelehnt', null);
            return Response::error(403, $e->getMessage());
        } catch (AuthError $e) {
            return match ($e->reason) {
                AuthError::PASSWORD_TOO_SHORT => Response::json(400, ['error' => $e->getMessage(), 'path' => 'password']),
                AuthError::UNKNOWN_USER => Response::json(400, ['error' => $e->getMessage(), 'path' => 'username']),
                default => throw $e,
            };
        }
        $this->audit->request($r, 'notfall_abgeschlossen', null, ['konto' => $id]);
        return Response::empty();
    }
}
