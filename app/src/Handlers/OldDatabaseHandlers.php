<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;

// Antwort bei einer Datenbank vom Stand vor dem Plugin-Archiv (Db\Migrator::isPreArchive): Statt Fehlern zeigt jede Seite
// die Schritte (sichern, löschen, neu einrichten, neu koppeln), die API antwortet 503 mit MESSAGE. Eine Umstellung gibt
// es nicht; die Datenbank bleibt unverändert. Das CSS liefert WebHandlers auch hier nicht, deshalb diese Klasse selbst.
final class OldDatabaseHandlers
{
    /** Meldung der API (503); das Plugin zeigt sie bei Koppeln und Liefern. */
    public const MESSAGE = 'Die Datenbank des Servers stammt von einer älteren Version; der Betreiber muss sie sichern, löschen und tokenlore neu einrichten (Anleitung auf der Webseite).';

    /** Merkmal der API-Antwort, an dem das Plugin diesen Fall von einem ausgelasteten Server (503) unterscheidet. */
    public const REASON = 'old_database';

    public static function register(Router $router): void
    {
        $router->apiFallback(static fn(): Response => Response::json(503, ['error' => self::MESSAGE, 'reason' => self::REASON]));
        $router->fallback(static function (Request $r): Response {
            if (($r->query['asset'] ?? null) === SetupHandlers::CSS_ASSET) {
                return SetupHandlers::stylesheet();
            }
            return (new Response(503, self::render(['css' => $r->scriptBase . '/index.php?asset=' . SetupHandlers::CSS_ASSET])))
                ->withHeader('Content-Type', 'text/html; charset=utf-8')
                ->withHeader('Cache-Control', 'no-store');
        });
    }

    /** @param array<string,mixed> $v */
    private static function render(array $v): string
    {
        return (static function (array $v): string {
            ob_start();
            try {
                require dirname(__DIR__, 2) . '/templates/old-database.php';
                return (string) ob_get_contents();
            } finally {
                ob_end_clean();
            }
        })($v);
    }
}
