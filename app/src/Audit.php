<?php

declare(strict_types=1);

namespace Tokenlore;

use Closure;
use LogicException;
use Tokenlore\Http\Request;

// Sicherheitsereignisse ins Protokoll (wie internal/audit im Go-Server): je Ereignis eine Zeile
// „sicherheit {JSON}“ mit Ereignisname, Nutzer-ID (0: unbekannt), IP und Objekt-IDs. Nie Passwörter,
// Codes, Schlüssel, Token, Namen oder rohe Eingaben; Felder mit verräterischem Namen werden abgewiesen.
final class Audit
{
    private const SECRET_FIELD = '/pass|pw|code|key|token|secret|csrf/i';

    private readonly Closure $log;

    /** @param (callable(string): void)|null $log Ziel der Zeilen (Standard: error_log) */
    public function __construct(?callable $log = null)
    {
        $this->log = $log === null ? static function (string $line): void {
            error_log($line);
        } : Closure::fromCallable($log);
    }

    /** @param array<string,int|string> $fields Objekt-IDs, Anzahlen, Wege – nichts Geheimes */
    public function event(string $name, ?int $uid, array $fields = []): void
    {
        foreach (array_keys($fields) as $key) {
            if (preg_match(self::SECRET_FIELD, (string) $key) === 1) {
                throw new LogicException('Feld gehört nicht ins Sicherheitsprotokoll: ' . $key);
            }
        }
        // JSON maskiert Zeilenumbrüche: ein Ereignis bleibt eine Zeile.
        ($this->log)('sicherheit ' . json_encode(['ereignis' => $name, 'nutzer' => $uid ?? 0] + $fields,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
    }

    /**
     * Ereignis einer HTTP-Anfrage mit Client-IP. Die IP legt die Middleware ab (limitIp, requireSession; mit
     * derselben Proxy-Regel wie die Ratengrenze), sonst gilt REMOTE_ADDR.
     *
     * @param array<string,int|string> $fields
     */
    public function request(Request $r, string $name, ?int $uid, array $fields = []): void
    {
        $this->event($name, $uid, ['ip' => (string) $r->attr('ip', $r->clientIp(false))] + $fields);
    }
}
