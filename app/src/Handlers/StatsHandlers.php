<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Db\Database;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Stats\Lists;
use Tokenlore\Stats\ParamError;
use Tokenlore\Stats\Stats;

// Routen der Statistik (wie stats_handlers.go): GET /api/stats, /api/models, /api/accounts.
// Alle mit Sitzung; die Gleichzeitigkeitsgrenze des Go-Servers (limitStats) entfällt laut Design.
final class StatsHandlers
{
    private function __construct(private readonly Database $db, private readonly Closure $clock)
    {
    }

    /** @param (callable(): int)|null $clock Unix-Sekunden (Standard: time()) */
    public static function register(Router $router, Middleware $mw, Database $db, ?callable $clock = null): void
    {
        $h = new self($db, $clock === null ? time(...) : Closure::fromCallable($clock));
        $sess = static fn(callable $handler): callable => Middleware::chain($handler, $mw->requireSession(), $mw->requireCsrf());
        $router->add('GET', '/api/stats', $sess($h->stats(...)));
        $router->add('GET', '/api/models', $sess($h->models(...)));
        $router->add('GET', '/api/accounts', $sess($h->accounts(...)));
    }

    /** 400 mit Parametername, ohne Eingabewert. */
    public static function paramError(ParamError $e): Response
    {
        return Response::json(400, ['error' => $e->getMessage(), 'path' => $e->path]);
    }

    private function stats(Request $r): Response
    {
        try {
            return Response::json(200, (new Stats($this->db, $this->clock))->forUser((int) $r->attr('uid'), $r->query));
        } catch (ParamError $e) {
            return self::paramError($e);
        }
    }

    private function models(Request $r): Response
    {
        try {
            [$f] = Stats::parseQuery($r->query, ($this->clock)());
        } catch (ParamError $e) {
            return self::paramError($e);
        }
        return Response::json(200, (new Lists($this->db))->models((int) $r->attr('uid'), $f));
    }

    private function accounts(Request $r): Response
    {
        try {
            [$f] = Stats::parseQuery($r->query, ($this->clock)());
        } catch (ParamError $e) {
            return self::paramError($e);
        }
        return Response::json(200, (new Lists($this->db))->accounts((int) $r->attr('uid'), $f));
    }
}
