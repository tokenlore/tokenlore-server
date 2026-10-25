<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Config\BaseUrl;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Devices\Devices;
use Tokenlore\Devices\Pairing;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Protocol\Limits;
use Tokenlore\Util\Names;
use Tokenlore\Util\Time;

// Geräte der angemeldeten Nutzer (internal/httpapi/device_handlers.go, manage_handlers.go): Kopplungscode erzeugen,
// auflisten, sperren, umbenennen. Alle Routen verlangen Sitzung und CSRF-Token (bei GET entfällt es).
final class DeviceHandlers
{
    private const NOT_FOUND = 'Gerät nicht gefunden';

    private function __construct(
        private readonly Pairing $pairing,
        private readonly Devices $devices,
        private readonly ServerSettings $settings,
        private readonly Closure $clock,
        private readonly Audit $audit,
    ) {
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time())
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     */
    public static function register(
        Router $router,
        Middleware $mw,
        Pairing $pairing,
        Devices $devices,
        ServerSettings $settings,
        ?callable $clock = null,
        ?Audit $audit = null,
    ): void {
        $h = new self($pairing, $devices, $settings, $clock === null ? time(...) : Closure::fromCallable($clock), $audit ?? new Audit());
        $session = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf());
        $router->add('POST', '/api/devices/pair-codes', $session($h->pairCode(...)));
        $router->add('GET', '/api/devices', $session($h->list(...)));
        $router->add('POST', '/api/devices/{id}/revoke', $session($h->revoke(...)));
        $router->add('PUT', '/api/devices/{id}/name', Middleware::chain(
            $h->rename(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->jsonOnly(),
            $mw->maxBody(4096),
        ));
    }

    /** @param array<string,string> $params */
    private function pairCode(Request $r, array $params): Response
    {
        $c = $this->pairing->newCode((int) $r->attr('uid'), ($this->clock)());
        $this->audit->request($r, 'kopplungscode', (int) $r->attr('uid'));
        $fingerprint = $this->settings->caFingerprint();
        // Gleicher Wortlaut wie „admin pair-code“; --ca nur mit hinterlegtem Zertifikat.
        $command = '/tokenlore:connect ' . BaseUrl::effective($r, $this->settings->publicUrl(), $this->settings->trustProxy())
            . ' ' . $c['code'] . ($fingerprint === '' ? '' : ' --ca ' . $fingerprint);
        return Response::json(200, [
            'code' => $c['code'],
            'expires_at' => Time::isoMs($c['expires_at'] * 1000),
            'ca_fingerprint' => $fingerprint,
            'command' => $command,
        ]);
    }

    /** @param array<string,string> $params */
    private function list(Request $r, array $params): Response
    {
        return Response::json(200, $this->devices->list((int) $r->attr('uid')));
    }

    /** @param array<string,string> $params */
    private function revoke(Request $r, array $params): Response
    {
        $id = self::deviceId($params['id'] ?? '');
        if ($id === null || !$this->devices->revoke((int) $r->attr('uid'), $id, ($this->clock)())) {
            return Response::error(404, self::NOT_FOUND);
        }
        $this->audit->request($r, 'geraet_gesperrt', (int) $r->attr('uid'), ['geraet' => $id]);
        return Response::empty();
    }

    /** @param array<string,string> $params */
    private function rename(Request $r, array $params): Response
    {
        $body = StrictJson::strings($r->body, ['name']);
        if ($body === null) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        if (Names::clean($body['name']) === null) {
            return Response::error(400, sprintf('Gerätename ungültig (1 bis %d Zeichen, keine Steuer- oder Formatzeichen)', Limits::MAX_DEVICE_NAME));
        }
        $id = self::deviceId($params['id'] ?? '');
        if ($id === null || !$this->devices->rename((int) $r->attr('uid'), $id, $body['name'])) {
            return Response::error(404, self::NOT_FOUND);
        }
        $this->audit->request($r, 'geraet_umbenannt', (int) $r->attr('uid'), ['geraet' => $id]);
        return Response::empty();
    }

    /** Geräte-ID aus dem Pfad: positive Ganzzahl; sonst null (Antwort 404). */
    private static function deviceId(string $s): ?int
    {
        // Mehr als 18 Stellen passen in keine vergebene ID und würden int überlaufen.
        return preg_match('/^[0-9]{1,18}\z/', $s) === 1 && (int) $s > 0 ? (int) $s : null;
    }
}
