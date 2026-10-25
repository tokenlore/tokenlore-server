<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Devices\BadCodeException;
use Tokenlore\Devices\Pairing;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Protocol\Limits;
use Tokenlore\Protocol\Validator;

// Routen des Plugins ohne Sitzung (internal/httpapi/device_handlers.go): Kopplung und CA-Abruf.
// Die Datenannahme (POST /api/plugin/ingest) liegt in einer eigenen Klasse.
final class PluginHandlers
{
    private function __construct(
        private readonly Pairing $pairing,
        private readonly ServerSettings $settings,
        private readonly Closure $clock,
        private readonly Audit $audit,
    ) {
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time())
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     */
    public static function register(Router $router, Middleware $mw, Pairing $pairing, ServerSettings $settings, ?callable $clock = null, ?Audit $audit = null): void
    {
        $h = new self($pairing, $settings, $clock === null ? time(...) : Closure::fromCallable($clock), $audit ?? new Audit());
        $router->add('POST', '/api/plugin/pair', Middleware::chain($h->pair(...), $mw->limitIp('pair'), $mw->jsonOnly(), $mw->maxBody(4096)));
        // Öffentlich, damit das Plugin vor dem Koppeln den Fingerabdruck vergleichen kann; die IP-Grenze greift vor jedem Zugriff.
        $router->add('GET', '/api/plugin/ca', Middleware::chain($h->ca(...), $mw->limitIp('ca')));
    }

    /** @param array<string,string> $params */
    private function pair(Request $r, array $params): Response
    {
        $req = StrictJson::strings($r->body, ['code', 'device_name', 'os', 'arch']);
        if ($req === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        if (preg_match('/^[0-9]{6}\z/', $req['code']) !== 1) {
            return Response::error(400, 'Code muss aus 6 Ziffern bestehen');
        }
        if (!Validator::deviceName($req['device_name'])) {
            return Response::error(400, sprintf('Gerätename ungültig (1 bis %d Zeichen, keine Steuer- oder Formatzeichen)', Limits::MAX_DEVICE_NAME));
        }
        if (!in_array($req['os'], ['windows', 'linux', 'darwin'], true)) {
            return Response::error(400, 'Betriebssystem ungültig');
        }
        if (!in_array($req['arch'], ['amd64', 'arm64'], true)) {
            return Response::error(400, 'Architektur ungültig');
        }
        try {
            $paired = $this->pairing->redeem($req['code'], $req['device_name'], $req['os'], $req['arch'], ($this->clock)());
        } catch (BadCodeException $e) {
            $this->audit->request($r, 'kopplung_fehlgeschlagen', null);
            return Response::error(401, $e->getMessage());
        }
        $this->audit->request($r, 'geraet_gekoppelt', $paired['user_id'], ['geraet' => $paired['device_id']]);
        return Response::json(200, [
            'device_id' => $paired['device_id'],
            'device_key' => $paired['key'],
            'project_salt' => $paired['project_salt'],
            // Leer ohne hinterlegtes Zertifikat: das Plugin prüft dann wie ein Browser.
            'ca_fingerprint' => $this->settings->caFingerprint(),
        ]);
    }

    /**
     * Das öffentliche CA-Zertifikat. Ausgegeben wird nur der neu kodierte erste CERTIFICATE-Block
     * (siehe ServerSettings), nie Rohtext; ohne hinterlegtes Zertifikat 404.
     *
     * @param array<string,string> $params
     */
    private function ca(Request $r, array $params): Response
    {
        $pem = $this->settings->caPem();
        if ($pem === null) {
            return Response::error(404, 'Nicht gefunden');
        }
        return (new Response(200, $pem))->withHeader('Content-Type', 'application/x-pem-file');
    }
}
