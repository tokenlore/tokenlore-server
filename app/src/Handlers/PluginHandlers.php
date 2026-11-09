<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Devices\BadCodeException;
use Tokenlore\Devices\Pairing;
use Tokenlore\Devices\ProofReused;
use Tokenlore\Devices\SourceTaken;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Protocol\Limits;
use Tokenlore\Protocol\Signature;
use Tokenlore\Protocol\Validator;

// Routen des Plugins ohne Sitzung (internal/httpapi/device_handlers.go): Kopplung, CA-Abruf und Server-Kennung.
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
        // Öffentlich, damit das Plugin vor dem Koppeln device_source aus server_id bilden kann; IP-Grenze wie beim CA-Abruf.
        $router->add('GET', '/api/plugin/info', Middleware::chain($h->info(...), $mw->limitIp('info')));
    }

    /**
     * Kennung des Servers und älteste angenommene Plugin-Version. Beides ist öffentlich: server_id ist ohne die
     * Kennung des Rechners wertlos, die Mindestversion steht im Code.
     *
     * @param array<string,string> $params
     */
    private function info(Request $r, array $params): Response
    {
        return Response::json(200, [
            'server_id' => $this->settings->serverId(),
            'min_plugin_version' => Limits::MIN_PLUGIN_VERSION,
        ]);
    }

    /**
     * Koppeln laut Abschnitt „Koppeln“ in protocol/doc.md. Prüfreihenfolge: Form des Rumpfs (400), Plugin-Version
     * (400, zu alt 426 vor jeder weiteren Prüfung, der Code bleibt gültig), dann die übrigen Felder (400), darunter der
     * Besitznachweis sign_public_key_proof direkt nach dem Signaturschlüssel und vor dem Einlösen des Codes. Jeder
     * Feldfehler nennt das Feld in path, nie einen Wert aus dem Rumpf.
     *
     * @param array<string,string> $params
     */
    private function pair(Request $r, array $params): Response
    {
        $text = ['code', 'device_name', 'os', 'arch', 'device_source', 'plugin_version', 'sign_public_key', 'sign_public_key_proof'];
        [$v, , $field] = StrictJson::decode($r->body, array_fill_keys($text, 'string')
            + ['device_name_explicit' => 'bool', 'sign_public_keys_previous' => 'string[]']);
        $bad = static fn(string $msg, string $path): Response => Response::json(400, ['error' => $msg, 'path' => $path]);
        if ($v === null) {
            return $field === '' ? Response::error(400, 'Ungültige Anfrage') : $bad('Ungültige Anfrage', $field);
        }
        $req = array_merge(array_fill_keys($text, ''), $v);
        // Fehlt das Feld (älteres Plugin), gilt der Name als nicht ausdrücklich gewählt.
        $explicit = ($v['device_name_explicit'] ?? false) === true;
        if (preg_match(Limits::VERSION_PATTERN, $req['plugin_version']) !== 1) {
            return $bad('Plugin-Version ungültig', 'plugin_version');
        }
        if (Validator::pluginOutdated($req['plugin_version'])) {
            return Response::json(426, ['error' => 'plugin_outdated', 'min_plugin_version' => Limits::MIN_PLUGIN_VERSION]);
        }
        if (preg_match('/^[0-9]{6}\z/', $req['code']) !== 1) {
            return $bad('Code muss aus 6 Ziffern bestehen', 'code');
        }
        if (!Validator::deviceName($req['device_name'])) {
            return $bad(sprintf('Gerätename ungültig (1 bis %d Zeichen, keine Steuer- oder Formatzeichen)', Limits::MAX_DEVICE_NAME), 'device_name');
        }
        if (!in_array($req['os'], ['windows', 'linux', 'darwin'], true)) {
            return $bad('Betriebssystem ungültig', 'os');
        }
        if (!in_array($req['arch'], ['amd64', 'arm64'], true)) {
            return $bad('Architektur ungültig', 'arch');
        }
        if (!Validator::deviceSource($req['device_source'])) {
            return $bad('Gerätekennung ungültig (64 Hex-Zeichen, klein)', 'device_source');
        }
        $signKey = Validator::signKey($req['sign_public_key']);
        if ($signKey === null) {
            return $bad('Signaturschlüssel ungültig (Base64, 32 Byte)', 'sign_public_key');
        }
        // Besitznachweis vor jeder Verwendung des Schlüssels: Wer einen fremden öffentlichen Schlüssel nur kennt,
        // kann ihn nicht als seinen melden und so das echte Gerät aussperren. Die server_id im Nachweis verhindert, dass
        // ein auf einem anderen Server mitgelesener Nachweis hier gilt. Gegen einen falschen Server, der diese server_id
        // meldet, schützt sie nicht; dagegen gewinnt der neueste gültige Nachweis (Pairing::redeem).
        if (!Signature::verifyPairProof($this->settings->serverId(), $req['code'], $req['sign_public_key_proof'], $signKey)) {
            return $bad('Besitznachweis des Signaturschlüssels fehlt oder passt nicht', 'sign_public_key_proof');
        }
        $previous = $v['sign_public_keys_previous'] ?? [];
        if (count($previous) > Limits::MAX_SIGN_KEYS_PREVIOUS) {
            return $bad(sprintf('Zu viele frühere Signaturschlüssel (höchstens %d)', Limits::MAX_SIGN_KEYS_PREVIOUS), 'sign_public_keys_previous');
        }
        $previousRaw = [];
        foreach ($previous as $i => $p) {
            $raw = Validator::signKey($p);
            if ($raw === null) {
                return $bad('Signaturschlüssel ungültig (Base64, 32 Byte)', "sign_public_keys_previous[$i]");
            }
            $previousRaw[] = $raw;
        }
        try {
            $paired = $this->pairing->redeem(
                $req['code'], $req['device_name'], $req['os'], $req['arch'], $req['device_source'], ($this->clock)(), $explicit,
                $signKey, $previousRaw, $req['plugin_version'],
            );
        } catch (BadCodeException $e) {
            $this->audit->request($r, 'kopplung_fehlgeschlagen', null);
            return Response::error(401, $e->getMessage());
        } catch (SourceTaken $e) {
            $this->audit->request($r, 'kopplung_abgelehnt', $e->userId);
            return Response::error(409, $e->getMessage());
        } catch (ProofReused $e) {
            // Ein Nachweis gilt nur einmal (Entscheidung Z9 a); der Code bleibt gültig.
            $this->audit->request($r, 'kopplung_abgelehnt', $e->userId);
            return $bad($e->getMessage(), 'sign_public_key_proof');
        }
        $this->audit->request($r, $paired['repaired'] ? 'geraet_neu_gekoppelt' : 'geraet_gekoppelt', $paired['user_id'], ['geraet' => $paired['device_id']]);
        return Response::json(200, [
            'device_id' => $paired['device_id'],
            'device_key' => $paired['key'],
            // Leer ohne hinterlegtes Zertifikat: das Plugin prüft dann wie ein Browser.
            'ca_fingerprint' => $this->settings->caFingerprint(),
            'repaired' => $paired['repaired'],
            // Kanonisches Base64 (Validator::signKey), also genau wie gesendet.
            'sign_keys_refused' => array_map('base64_encode', $paired['sign_keys_refused']),
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
