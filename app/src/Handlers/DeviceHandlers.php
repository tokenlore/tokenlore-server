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
use Tokenlore\Util\MediaType;
use Tokenlore\Util\Names;
use Tokenlore\Util\Time;

// Geräte der angemeldeten Nutzer (internal/httpapi/device_handlers.go, manage_handlers.go): Kopplungscode erzeugen,
// auflisten (mit Hinweisen zum Zusammenlegen und Fragen nach dem Vorgänger), sperren, umbenennen, zusammenlegen, die
// Frage nach dem Vorgänger beantworten. Alle Routen verlangen Sitzung und CSRF-Token (bei GET entfällt es).
final class DeviceHandlers
{
    private const NOT_FOUND = 'Gerät nicht gefunden';

    private function __construct(
        private readonly Pairing $pairing,
        private readonly Devices $devices,
        private readonly ServerSettings $settings,
        private readonly Closure $clock,
        private readonly Audit $audit,
        private readonly Closure $log,
    ) {
    }

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time())
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     * @param (callable(string): void)|null $log Ziel für Fehlermeldungen (Standard: error_log)
     */
    public static function register(
        Router $router,
        Middleware $mw,
        Pairing $pairing,
        Devices $devices,
        ServerSettings $settings,
        ?callable $clock = null,
        ?Audit $audit = null,
        ?callable $log = null,
    ): void {
        $h = new self(
            $pairing,
            $devices,
            $settings,
            $clock === null ? time(...) : Closure::fromCallable($clock),
            $audit ?? new Audit(),
            $log === null ? static function (string $m): void {
                error_log($m);
            } : Closure::fromCallable($log),
        );
        $session = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf());
        $router->add('POST', '/api/devices/pair-codes', Middleware::chain(
            $h->pairCode(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->maxBody(4096),
        ));
        $router->add('GET', '/api/devices', $session($h->list(...)));
        $router->add('POST', '/api/devices/{id}/revoke', $session($h->revoke(...)));
        $router->add('POST', '/api/devices/{id}/merge', Middleware::chain(
            $h->merge(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->jsonOnly(),
            $mw->maxBody(4096),
        ));
        $router->add('POST', '/api/devices/{id}/predecessor', Middleware::chain(
            $h->predecessor(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->jsonOnly(),
            $mw->maxBody(4096),
        ));
        $router->add('PUT', '/api/devices/{id}/name', Middleware::chain(
            $h->rename(...),
            $mw->requireSession(),
            $mw->requireCsrf(),
            $mw->jsonOnly(),
            $mw->maxBody(4096),
        ));
    }

    /**
     * Neuer Kopplungscode. Rumpf leer: für ein neues Gerät oder das Gerät der Kennung. Rumpf {"device_id": n}
     * (JSON): für dieses eigene Gerät, das beim Einlösen neu gekoppelt wird; fremd oder unbekannt: 404.
     *
     * @param array<string,string> $params
     */
    private function pairCode(Request $r, array $params): Response
    {
        $deviceId = null;
        if (trim($r->body) !== '') {
            if (MediaType::parse($r->header('content-type') ?? '') !== 'application/json') {
                return Response::error(415, 'Content-Type muss application/json sein');
            }
            [$body] = StrictJson::decode($r->body, ['device_id' => 'int']);
            if ($body === null) {
                return Response::error(400, 'Ungültige Anfrage');
            }
            if (isset($body['device_id'])) {
                $deviceId = $body['device_id'];
                if ($deviceId < 1) {
                    return Response::error(404, self::NOT_FOUND);
                }
            }
        }
        $c = $this->pairing->newCode((int) $r->attr('uid'), ($this->clock)(), $deviceId);
        if ($c === null) {
            return Response::error(404, self::NOT_FOUND);
        }
        $this->audit->request($r, 'kopplungscode', (int) $r->attr('uid'), $deviceId === null ? [] : ['geraet' => $deviceId]);
        $fingerprint = $this->settings->caFingerprint();
        // Gleicher Wortlaut wie „admin pair-code“; --ca nur mit hinterlegtem Zertifikat.
        $command = '/tokenlore:connect ' . BaseUrl::effective($r, $this->settings->publicUrl(), $this->settings->trustProxy())
            . ' ' . $c['code'] . ($fingerprint === '' ? '' : ' --ca ' . $fingerprint);
        return Response::json(200, [
            'code' => $c['code'],
            'expires_at' => Time::isoMs($c['expires_at'] * 1000),
            'ca_fingerprint' => $fingerprint,
            'command' => $command,
            'device' => $c['device'],
        ]);
    }

    /**
     * Geräte des Nutzers, Hinweise zum Zusammenlegen und offene Fragen nach dem Vorgänger:
     * {"devices": [...], "merge_hints": [{"from": B, "into": A}], "predecessor_hints": [{"device_id": B,
     * "predecessor": {…}, "recommended": "same"|"new", "overlap_days": n}]} (Devices::predecessorHints).
     * Scheitert das Berechnen der Hinweise, kommt die Liste trotzdem, mit leeren Hinweisen; der Fehler geht ins Log.
     *
     * @param array<string,string> $params
     */
    private function list(Request $r, array $params): Response
    {
        $uid = (int) $r->attr('uid');
        $devices = $this->devices->list($uid);
        $hints = $this->hints('Hinweise zum Zusammenlegen', fn(): array => $this->devices->mergeCandidates($uid));
        $pred = $this->hints('Fragen nach dem Vorgänger', fn(): array => $this->devices->predecessorHints($uid, ($this->clock)()));
        return Response::json(200, ['devices' => $devices, 'merge_hints' => $hints, 'predecessor_hints' => $pred]);
    }

    /**
     * Hinweise aus $fn; bei einem Fehler eine leere Liste, die Ursache ins Fehlerprotokoll (wie Kernel::handle: nach
     * außen nichts).
     *
     * @param callable(): list<mixed> $fn
     * @return list<mixed>
     */
    private function hints(string $what, callable $fn): array
    {
        try {
            return $fn();
        } catch (\Throwable $e) {
            ($this->log)(sprintf('%s: %s: %s in %s:%d', $what, $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
            return [];
        }
    }

    /**
     * Antwort auf die Frage nach dem Vorgänger für Gerät {id} (B) mit {"answer": "same"|"new"} (Devices::answerPredecessor).
     * Andere Antwort oder Rumpf: 400; kein offenes Paar für B beim Nutzer (unbekannt, fremd, schon beantwortet): 404.
     *
     * @param array<string,string> $params
     */
    private function predecessor(Request $r, array $params): Response
    {
        $body = StrictJson::strings($r->body, ['answer']);
        if ($body === null || !in_array($body['answer'], ['same', 'new'], true)) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        $id = self::deviceId($params['id'] ?? '');
        $uid = (int) $r->attr('uid');
        $a = $id === null ? null : $this->devices->answerPredecessor($uid, $id, $body['answer'], ($this->clock)());
        if ($a === null) {
            return Response::error(404, self::NOT_FOUND);
        }
        $this->audit->request($r, 'vorgaenger_beantwortet', $uid, ['geraet' => $id, 'vorgaenger' => $a, 'antwort' => $body['answer']]);
        return Response::empty();
    }

    /**
     * Legt das Gerät aus dem Rumpf {"from": B} in das Gerät {id} (A) zusammen. B gleich A: 400; eines davon
     * unbekannt oder fremd: 404.
     *
     * @param array<string,string> $params
     */
    private function merge(Request $r, array $params): Response
    {
        [$body] = StrictJson::decode($r->body, ['from' => 'int']);
        if ($body === null || !isset($body['from'])) {
            return Response::error(400, 'Ungültige Anfrage');
        }
        $into = self::deviceId($params['id'] ?? '');
        $from = $body['from'];
        if ($into === null || $from < 1) {
            return Response::error(404, self::NOT_FOUND);
        }
        if ($into === $from) {
            return Response::error(400, 'Ein Gerät lässt sich nicht mit sich selbst zusammenlegen');
        }
        $uid = (int) $r->attr('uid');
        if (!$this->devices->merge($uid, $into, $from)) {
            return Response::error(404, self::NOT_FOUND);
        }
        $this->audit->request($r, 'geraete_zusammengelegt', $uid, ['geraet' => $into, 'von' => $from]);
        return Response::empty();
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
