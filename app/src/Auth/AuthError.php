<?php

declare(strict_types=1);

namespace Tokenlore\Auth;

// Erwartbare Fehler von Konten und Sitzungen (wie die Err…-Werte in internal/auth). $reason sagt,
// welcher es ist; die Handler leiten daraus Status und Text ab, die Meldung entspricht dem Go-Text.
final class AuthError extends \RuntimeException
{
    public const BAD_CREDENTIALS = 'bad_credentials';
    public const LOCKED = 'locked';
    public const UNKNOWN_USER = 'unknown_user';
    public const PASSWORD_TOO_SHORT = 'password_too_short';
    public const INVALID_USERNAME = 'invalid_username';
    public const USERNAME_TAKEN = 'username_taken';
    public const INVALID_ROLE = 'invalid_role';

    private const MESSAGES = [
        self::BAD_CREDENTIALS => 'Anmeldung fehlgeschlagen',
        self::LOCKED => 'Konto vorübergehend gesperrt',
        self::UNKNOWN_USER => 'Nutzer unbekannt',
        self::PASSWORD_TOO_SHORT => 'Passwort zu kurz: mindestens ' . Users::MIN_PASSWORD_LEN . ' Zeichen',
        self::INVALID_USERNAME => 'Ungültiger Benutzername: 3 bis 32 Zeichen aus a-z, 0-9, Punkt, Unterstrich und Bindestrich',
        self::USERNAME_TAKEN => 'Benutzername schon vergeben',
        self::INVALID_ROLE => 'Ungültige Rolle',
    ];

    /** $uid: betroffenes Konto, wenn bekannt (nur fürs Sicherheitsprotokoll, nie nach außen). */
    private function __construct(public readonly string $reason, public readonly ?int $uid)
    {
        parent::__construct(self::MESSAGES[$reason]);
    }

    public static function of(string $reason, ?int $uid = null): self
    {
        return new self($reason, $uid);
    }
}
