<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Auth\AuthError;
use Tokenlore\Auth\Users;
use Tokenlore\Config\BaseUrl;
use Tokenlore\Config\Paths;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Setup\Requirements;
use Tokenlore\Setup\SelfFetch;
use Tokenlore\Setup\Setup;
use Tokenlore\Setup\SetupClosed;

// Die Einrichtung im Browser: eine schlichte PHP-Seite (app/templates/setup.php mit setup.css, ohne Skript und
// ohne Inline-Stil, also unter der strengen CSP), die auch ohne Datenbank läuft. Solange Setup::needed()
// gilt, ist sie für jede Seitenanfrage die Antwort und die API antwortet 503; danach (ein Konto existiert)
// 404 – dauerhaft.
//
// Ablauf: GET zeigt Voraussetzungen, Hinweise und Formular; POST (nur auf der Startadresse) prüft das Token
// (Doppel-Cookie: kurzlebiges Cookie tl_setup und gleiches Feld csrf), die Voraussetzungen, den Datenordner (von außen
// abrufbar: kein Abschluss), die Nachweisdatei (Setup::PROOF_FILE mit dem Code zu diesem Token) und die Eingaben und ruft
// Setup::run. Der Abschluss zeigt die Bestätigung und prüft den Datenordner noch einmal von außen (mit einer Wegwerf-Probedatei, nie mit dem Namen der Datenbank).
final class SetupHandlers
{
    private const COOKIE = 'tl_setup';
    // Über https mit __Host-: Nur diese Adresse selbst (sicher, Path=/, ohne Domain) darf es setzen. Eine Nachbar-Subdomain
    // oder ein Angreifer im Netz kann dem Besitzer so kein eigenes Token unterschieben, dessen Nachweis-Code er kennt.
    private const HOST_COOKIE = '__Host-tl_setup';
    // Lang genug, um die Nachweisdatei per FTP hochzuladen: Ihr Code hängt am Token dieses Cookies.
    private const COOKIE_TTL = 7200;
    private const MAX_BODY = 8192;
    /** index.php?asset=setup.css: das CSS der Seite; WebHandlers liefert es auch nach der Einrichtung aus. */
    public const CSS_ASSET = 'setup.css';
    private const API_DEPTH = 6;

    // Das Setup der Anfrage, für die es zuletzt gebaut wurde (siehe setupFor).
    private ?Request $setupRequest = null;
    private ?Setup $setup = null;

    private function __construct(
        private readonly Paths $paths,
        private readonly ?Closure $fetch,
        private readonly ?Closure $env,
    ) {
    }

    /**
     * Trägt die Einrichtung ein: den Rückfall für alle Seiten außerhalb von /api/ und Platzhalter für /api/…
     * (bis sechs Pfadsegmente, alle gängigen Methoden), die 503 antworten. Vor jeder Antwort prüft sie erneut,
     * ob die Einrichtung noch nötig ist (sonst 404). Der Aufrufer (app/routes.php) trägt sie nur ein, solange
     * Setup::needed($paths) gilt, und lässt dann alles andere weg.
     *
     * @param (callable(string): ?array{status:int, head:string})|null $fetch Abrufer für die Selbstprüfungen
     *        (Standard: SelfFetch::forRequest, also die eigene Serveradresse); in Tests ein Fake
     * @param (callable(string): mixed)|null $env Prüffunktion für Requirements::check (nur Tests)
     */
    public static function register(Router $router, Paths $paths, ?callable $fetch = null, ?callable $env = null): void
    {
        $h = new self($paths, $fetch === null ? null : Closure::fromCallable($fetch), $env === null ? null : Closure::fromCallable($env));
        $router->fallback($h->page(...));
        for ($depth = 1; $depth <= self::API_DEPTH; $depth++) {
            $pattern = '/api/' . implode('/', array_map(static fn(int $i): string => '{s' . $i . '}', range(1, $depth)));
            foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as $method) {
                $router->add($method, $pattern, $h->api(...));
            }
        }
    }

    // Einmal je Anfrage gebaut (submit ruft bei Fehlern form auf, beide brauchen es): Der Abrufer verbindet zur eigenen
    // Serveradresse dieser Anfrage (SERVER_ADDR/SERVER_PORT). Die Anfrage selbst gilt als Schlüssel, damit ein Handler,
    // der mehrere Anfragen bedient (Tests), nie das Setup einer anderen erwischt.
    private function setupFor(Request $r): Setup
    {
        if ($this->setupRequest !== $r || $this->setup === null) {
            $this->setupRequest = $r;
            $this->setup = new Setup($this->paths, $this->fetch ?? SelfFetch::forRequest($r));
        }
        return $this->setup;
    }

    private function api(Request $r): Response
    {
        if (!Setup::needed($this->paths)) {
            return Response::error(404, 'Nicht gefunden');
        }
        if ($r->path === '/api/healthz') {
            // Für den Selbstabruf (Setup::authorizationArrives): nur ob ein Authorization-Header ankam, nie sein Inhalt.
            return Response::json(503, ['error' => Setup::NOT_READY, 'authorization' => $r->header('authorization') !== null]);
        }
        return Response::error(503, Setup::NOT_READY);
    }

    private function page(Request $r): Response
    {
        if (!Setup::needed($this->paths)) {
            return Response::text(404, 'Nicht gefunden');
        }
        if ($r->method === 'GET' || $r->method === 'HEAD') {
            if (($r->query['asset'] ?? null) === self::CSS_ASSET) {
                return self::stylesheet();
            }
            if ($r->method === 'HEAD') {
                // Kopfzeilen wie bei GET, aber ohne Prüfungen und Abrufe.
                return (new Response(200))->withHeader('Content-Type', 'text/html; charset=utf-8')->withHeader('Cache-Control', 'no-store');
            }
            return $this->form($r, 200, [], '');
        }
        if ($r->method === 'POST') {
            return $r->path === '/' ? $this->submit($r) : Response::text(404, 'Nicht gefunden');
        }
        return Response::text(405, 'Methode nicht erlaubt')->withHeader('Allow', 'GET, HEAD, POST');
    }

    /** Das CSS der Einrichtungsseite (statisch und harmlos, deshalb auch nach der Einrichtung abrufbar). */
    public static function stylesheet(): Response
    {
        $css = file_get_contents(self::templateDir() . '/setup.css');
        if ($css === false) {
            throw new \RuntimeException('setup.css fehlt in app/templates');
        }
        return (new Response(200, $css))
            ->withHeader('Content-Type', 'text/css; charset=utf-8')
            ->withHeader('Cache-Control', 'no-cache');
    }

    private function submit(Request $r): Response
    {
        $type = strtolower(trim(explode(';', $r->header('content-type') ?? '', 2)[0]));
        if ($type !== 'application/x-www-form-urlencoded') {
            return Response::text(415, 'Unsupported Media Type');
        }
        if (strlen($r->body) > self::MAX_BODY) {
            return Response::text(413, 'Anfrage zu groß');
        }
        parse_str($r->body, $fields);
        $text = static fn(string $name): ?string => isset($fields[$name]) && is_string($fields[$name]) ? $fields[$name] : null;

        $cookie = $r->cookie(self::cookieName($r));
        $sent = $text('csrf');
        if ($cookie === null || !self::validToken($cookie) || $sent === null || !hash_equals($cookie, $sent)) {
            return $this->form($r, 403, ['Die Sicherheitsprüfung ist fehlgeschlagen (das Formular war zu lange offen oder Cookies sind '
                . 'gesperrt). Bitte prüf die Eingaben und schick das Formular noch einmal ab.'], '');
        }

        $username = trim($text('username') ?? '');
        $password = $text('password') ?? '';
        $trust = ($text('trust_proxy') ?? '') === '1';

        $ctx = $this->context($r);
        if (Requirements::blocking($ctx['checks'])) {
            return $this->form($r, 400, ['Die Einrichtung ist erst möglich, wenn die als „Fehler“ markierten Punkte behoben sind.'], $username);
        }
        $setup = $this->setupFor($r);
        // Ist der Datenordner von außen abrufbar, bleibt die Einrichtung zu: Dort lägen Datenbank und Notfall-Code offen.
        if ($setup->dataFolderExposure(self::cleanBase($r, $trust)) === Setup::EXPOSED) {
            return $this->form($r, 400, ['Der Datenordner ist von außen abrufbar. Die Einrichtung ist erst möglich, wenn das behoben ist (Anleitung unten).'], $username);
        }
        if (!$setup->proofPresent($cookie)) {
            return $this->form($r, 400, ['Die Datei ' . Setup::PROOF_FILE . ' mit dem angezeigten Code liegt nicht im Datenordner. '
                . 'Leg sie per FTP dorthin (Schritt 3) und schick das Formular dann noch einmal ab.'], $username);
        }
        if ($password !== ($text('password2') ?? '')) {
            return $this->form($r, 400, ['Die beiden Passwörter stimmen nicht überein.'], $username);
        }
        try {
            Users::checkLength($password);
        } catch (AuthError $e) {
            return $this->form($r, 400, [$e->getMessage()], $username);
        }

        // Adresse für die Plugins: erkannt (mit der Proxy-Wahl des Formulars); wirken die Umschreibregeln nicht,
        // mit /index.php, sonst führten alle Adressen ins Leere.
        $detected = BaseUrl::detect($r, $trust);
        $rewrite = $setup->rewriteWorks(self::cleanBase($r, $trust));
        $store = $rewrite === false && !$r->viaIndexPhp ? $detected . '/index.php' : $detected;

        try {
            $setup->run($username, $password, $store, $trust);
        } catch (SetupClosed) {
            return Response::text(404, 'Nicht gefunden');
        } catch (AuthError $e) {
            return $this->form($r, 400, [$e->getMessage()], $username);
        }

        $exposure = $setup->dataFolderExposure(self::cleanBase($r, $trust));
        $html = self::render([
            'done' => true,
            'username' => $username,
            'storedUrl' => ServerSettings::validPublicUrl($store) ? rtrim($store, '/') : null,
            'exposure' => $exposure,
            'dataPath' => $setup->dataUrlPath(),
            'base' => self::cleanBase($r, $trust),
            'scriptBase' => $r->scriptBase,
            'rewrite' => $rewrite,
            // Ohne Umschreibregeln läuft die Seite nur über index.php (ihre API-Aufrufe hängen sich daran an).
            'next' => $rewrite === false ? $r->scriptBase . '/index.php' : self::actionUrl($r),
            'css' => self::cssUrl($r),
        ]);
        return self::html(200, $html)->withCookie(self::cookieName($r), '', $this->cookieOptions($r, 0));
    }

    /** Die Seite mit Voraussetzungen, Hinweisen und Formular (Status 200, bei Fehlern 400 oder 403). */
    private function form(Request $r, int $status, array $errors, string $username): Response
    {
        $ctx = $this->context($r);
        $blocking = Requirements::blocking($ctx['checks']);
        $base = self::cleanBase($r, $ctx['proxy']);
        // Abrufe nur, wenn der Server überhaupt laufen kann; sonst gibt es nichts zu prüfen.
        // Ein eigener Selbstabruf, der hier landet, prüft nicht noch einmal (sonst ruft sich der Server endlos
        // selbst auf, etwa wenn er auch die Probedatei an index.php gibt).
        $setup = $this->setupFor($r);
        $exposure = Setup::UNKNOWN;
        $rewrite = null;
        $authorization = null;
        if (!$blocking && $r->header('user-agent') !== SelfFetch::USER_AGENT) {
            $exposure = $setup->dataFolderExposure($base);
            $rewrite = $setup->rewriteWorks($base);
            $authorization = $setup->authorizationArrives($base, $rewrite);
        }
        $token = $r->cookie(self::cookieName($r));
        if ($token === null || !self::validToken($token)) {
            $token = bin2hex(random_bytes(32));
        }
        $detected = BaseUrl::detect($r, $ctx['proxy']);
        $proofPresent = !$blocking && $setup->proofPresent($token);
        $html = self::render([
            'done' => false,
            'checks' => $ctx['checks'],
            'critical' => Requirements::CRITICAL,
            'blocking' => $blocking,
            'https' => $ctx['https'],
            'proxySuggested' => $ctx['proxy'],
            'exposure' => $exposure,
            'rewrite' => $rewrite,
            'authorization' => $authorization,
            'dataPath' => $setup->dataUrlPath(),
            'base' => $base,
            'scriptBase' => $r->scriptBase,
            'storedUrl' => $rewrite === false && !$r->viaIndexPhp ? $detected . '/index.php' : $detected,
            'action' => self::actionUrl($r),
            'css' => self::cssUrl($r),
            'csrf' => $token,
            'proofFile' => Setup::PROOF_FILE,
            'proofCode' => Setup::proofCode($token),
            'proofPresent' => $proofPresent,
            'errors' => $errors,
            'username' => $username,
        ]);
        return self::html($status, $html)->withCookie(self::cookieName($r), $token, $this->cookieOptions($r, self::COOKIE_TTL));
    }

    /** @return array{checks: list<array{name:string, ok:bool, hint:string}>, proxy: bool, https: bool} */
    private function context(Request $r): array
    {
        $proxy = Setup::proxySuggested($r);
        $https = $r->isHttps($proxy);
        return ['checks' => Requirements::check($this->paths, $https, $this->env), 'proxy' => $proxy, 'https' => $https];
    }

    /** @return array{path:string,maxAge:int,secure:bool,httpOnly:bool,sameSite:string} */
    private function cookieOptions(Request $r, int $maxAge): array
    {
        // Secure nur, wenn der Besucher https nutzt: ein Secure-Cookie käme über http nie an. __Host- verlangt Path=/.
        $https = $r->isHttps(Setup::proxySuggested($r));
        return [
            'path' => $https || $r->scriptBase === '' ? '/' : $r->scriptBase,
            'maxAge' => $maxAge,
            'secure' => $https,
            'httpOnly' => true,
            // Lax statt Strict: Kommt der Besitzer über einen Link (Panel des Hosters, Mail) zurück, bleibt sein Token und
            // damit der Code der Nachweisdatei gleich. Fremde Formulare (POST) bekommen das Cookie auch bei Lax nicht.
            'sameSite' => 'Lax',
        ];
    }

    private static function cookieName(Request $r): string
    {
        return $r->isHttps(Setup::proxySuggested($r)) ? self::HOST_COOKIE : self::COOKIE;
    }

    /** Adresse der Anwendung ohne /index.php: dort wirken (oder fehlen) die Umschreibregeln. */
    private static function cleanBase(Request $r, bool $trustProxy): string
    {
        $base = BaseUrl::detect($r, $trustProxy);
        return $r->viaIndexPhp ? substr($base, 0, -strlen('/index.php')) : $base;
    }

    /** Startadresse, an die das Formular geht: dieselbe, über die die Seite kam (index.php nur, wenn es nötig war). */
    private static function actionUrl(Request $r): string
    {
        return $r->scriptBase . ($r->viaIndexPhp ? '/index.php' : '/');
    }

    // Immer über index.php?…: die Abfrage funktioniert auf jedem Server, ohne Umschreiben und ohne PATH_INFO.
    private static function cssUrl(Request $r): string
    {
        return $r->scriptBase . '/index.php?asset=' . self::CSS_ASSET;
    }

    private static function validToken(string $token): bool
    {
        return preg_match('/^[0-9a-f]{64}\z/', $token) === 1;
    }

    private static function templateDir(): string
    {
        return dirname(__DIR__, 2) . '/templates';
    }

    private static function html(int $status, string $html): Response
    {
        return (new Response($status, $html))
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store');
    }

    /** @param array<string,mixed> $v */
    private static function render(array $v): string
    {
        // Eigener Gültigkeitsbereich: das Template sieht nur $v.
        return (static function (array $v): string {
            ob_start();
            try {
                require self::templateDir() . '/setup.php';
                return (string) ob_get_contents();
            } finally {
                ob_end_clean();
            }
        })($v);
    }
}
