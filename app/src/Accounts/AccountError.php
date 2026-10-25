<?php

declare(strict_types=1);

namespace Tokenlore\Accounts;

use RuntimeException;

// Fehler der Kontoverwaltung (wie ErrNotFound und ErrInvalid in internal/accounts):
// NOT_FOUND gilt für unbekannte oder fremde Geräte, Konten und Zuordnungen, INVALID für Zeitraum, Kennung oder Namen.
final class AccountError extends RuntimeException
{
    public const NOT_FOUND = 'not_found';
    public const INVALID = 'invalid';

    private function __construct(public readonly string $kind, string $message)
    {
        parent::__construct($message);
    }

    public static function notFound(): self
    {
        return new self(self::NOT_FOUND, 'nicht gefunden');
    }

    public static function invalid(): self
    {
        return new self(self::INVALID, 'ungültige Eingabe');
    }
}
