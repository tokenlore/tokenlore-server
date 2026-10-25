<?php

declare(strict_types=1);

namespace Tokenlore\Http;

use Tokenlore\Util\GoJson;

// Antwort des Servers. Unveränderlich: with*() liefert eine Kopie.
//
// Der Inhalt steht im Speicher ($body im Konstruktor) oder in einer Datei ($file), die send() mit readfile()
// ausgibt, ohne sie ganz zu laden (große Dateien der Webseite). Gelesen wird er in beiden Fällen als $r->body; bei
// einer Datei liest erst dieser Zugriff sie (nur Tests und Aufrufer, die den Text brauchen, tun das).
//
// @property-read string $body
final class Response
{
    // \z statt $: ein Zeilenumbruch am Ende darf nicht durchrutschen.
    private const TOKEN = '/^[A-Za-z0-9!#$%&\'*+.^_`|~-]+\z/';
    private const COOKIE_VALUE = '/^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*\z/';
    private const COOKIE_PATH = '/^\/[\x21\x23-\x3A\x3C-\x7E]*\z/';

    /** @var array<string, array{string, string}> kleingeschriebener Name => [Name, Wert] */
    private array $headers = [];
    /** @var list<string> */
    private array $cookies = [];

    private readonly string $text;

    /** @param string|null $file Pfad der Datei, die statt $body ausgegeben wird (der Aufrufer prüft sie vorher) */
    public function __construct(public readonly int $status = 200, string $body = '', private readonly ?string $file = null)
    {
        $this->text = $body;
    }

    public function __get(string $name): string
    {
        if ($name !== 'body') {
            throw new \Error('Undefined property: ' . self::class . '::$' . $name);
        }
        if ($this->file === null) {
            return $this->text;
        }
        $content = @file_get_contents($this->file);
        return $content === false ? '' : $content;
    }

    public function __isset(string $name): bool
    {
        return $name === 'body';
    }

    /** JSON-Antwort in der Schreibweise von Go (Umlaute und Schrägstriche lesbar, < > & maskiert, Zahlen wie Go): siehe GoJson. */
    public static function json(int $status, mixed $data): self
    {
        return (new self($status, GoJson::encode($data) . "\n"))->withHeader('Content-Type', 'application/json');
    }

    /** Fehlerantwort `{"error": msg}`. */
    public static function error(int $status, string $msg): self
    {
        return self::json($status, ['error' => $msg]);
    }

    public static function text(int $status, string $body): self
    {
        return (new self($status, $body))->withHeader('Content-Type', 'text/plain; charset=utf-8');
    }

    /** Antwort ohne Inhalt (Standard 204). */
    public static function empty(int $status = 204): self
    {
        return new self($status);
    }

    /** Setzt den Header (ersetzt einen gleichnamigen). Zeilenumbrüche und ungültige Namen werden abgelehnt. */
    public function withHeader(string $name, string $value): self
    {
        if (!preg_match(self::TOKEN, $name) || preg_match('/[\x00-\x08\x0A-\x1F\x7F]/', $value)) {
            throw new \InvalidArgumentException('Ungültiger Header');
        }
        $c = clone $this;
        $c->headers[strtolower($name)] = [$name, $value];
        return $c;
    }

    /**
     * Fügt ein Set-Cookie hinzu. Optionen: path ('/'), maxAge (ohne: Sitzungscookie; 0 löscht),
     * secure (true), httpOnly (true), sameSite ('Strict'; auch 'Lax' oder 'None').
     *
     * @param array{path?:string,maxAge?:int,secure?:bool,httpOnly?:bool,sameSite?:string} $opts
     */
    public function withCookie(string $name, string $value, array $opts = []): self
    {
        $path = $opts['path'] ?? '/';
        $sameSite = $opts['sameSite'] ?? 'Strict';
        if (!preg_match(self::TOKEN, $name) || !preg_match(self::COOKIE_VALUE, $value)
            || !preg_match(self::COOKIE_PATH, $path)
            || !in_array($sameSite, ['Strict', 'Lax', 'None'], true)) {
            throw new \InvalidArgumentException('Ungültiges Cookie');
        }
        $line = $name . '=' . $value . '; Path=' . $path;
        if (isset($opts['maxAge'])) {
            $line .= '; Max-Age=' . $opts['maxAge'];
        }
        if ($opts['secure'] ?? true) {
            $line .= '; Secure';
        }
        if ($opts['httpOnly'] ?? true) {
            $line .= '; HttpOnly';
        }
        $c = clone $this;
        $c->cookies[] = $line . '; SameSite=' . $sameSite;
        return $c;
    }

    /** Wert eines Headers (Name ohne Beachtung der Schreibung) oder null. */
    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][1] ?? null;
    }

    /** @return array<string,string> Name => Wert, wie gesendet */
    public function headerLines(): array
    {
        $out = [];
        foreach ($this->headers as [$name, $value]) {
            $out[$name] = $value;
        }
        return $out;
    }

    /** @return list<string> Set-Cookie-Werte */
    public function cookieLines(): array
    {
        return $this->cookies;
    }

    /** Gibt Status, Header, Cookies und (außer bei HEAD: $withBody = false) den Inhalt aus. */
    public function send(bool $withBody = true): void
    {
        http_response_code($this->status);
        foreach ($this->headerLines() as $name => $value) {
            header($name . ': ' . $value);
        }
        foreach ($this->cookies as $cookie) {
            header('Set-Cookie: ' . $cookie, false);
        }
        if ($withBody) {
            $this->writeBody();
        }
    }

    /** Gibt den Inhalt aus; eine Datei Stück für Stück (readfile), nicht ganz im Speicher. */
    public function writeBody(): void
    {
        if ($this->file !== null) {
            @readfile($this->file);
            return;
        }
        echo $this->text;
    }
}
