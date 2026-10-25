<?php

declare(strict_types=1);

namespace Tokenlore\Setup;

use Tokenlore\Http\Request;

// Ein einziger, eng begrenzter HTTP-Abruf des Servers an sich selbst, für die Prüfungen der Einrichtung
// (Ist der Datenordner von außen abrufbar? Wirken die Umschreibregeln?).
//
// Die Adresse in der URL stammt aus dem Host-Header des Besuchers und ist damit nicht vertrauenswürdig.
// Deshalb gilt (gegen SSRF): Verbunden wird NIE mit dem Ziel aus der URL, sondern mit der eigenen
// Serveradresse (SERVER_ADDR und SERVER_PORT, nicht vom Client bestimmbar; Rückfall 127.0.0.1 und der
// Standardport). Den Namen aus der URL sendet der Abruf nur als Host-Header (und bei https als SNI-Name)
// mit, damit der richtige virtuelle Host antwortet. Es gibt keine DNS-Auflösung. Weitere Schranken:
//  - nur http und https in der URL, kein Benutzerteil, keine Steuerzeichen;
//  - ein Port in der URL (er geht nur in den Host-Header) muss der eigene Port, 80 oder 443 sein;
//  - zusätzliche Header nur geprüft (kein Zeilenumbruch, Host nicht überschreibbar);
//  - genau eine Anfrage, GET, HTTP/1.0, keine Weiterleitungen, höchstens $timeout Sekunden für alles, nur der
//    Anfang der Antwort wird gelesen;
//  - der Aufrufer zeigt nie Antworttext oder Fehlerursache an, nur eine Ja/Nein/Unklar-Aussage.
// Die Verschlüsselung (tls) richtet sich nach dem Server (hört er auf https?), nicht nach der Adresse in der URL;
// das Zertifikat wird nicht geprüft (es geht nur um „antwortet die Adresse mit der Datei“, es wird nichts Geheimes
// gesendet, und frische Installationen haben oft noch kein gültiges). Grenze: Der Abruf trifft den Server selbst.
// Steht davor ein Proxy, der Dateien selbst ausliefert, sieht er dessen Regeln nicht.
final class SelfFetch
{
    /** Länge des gelesenen Anfangs der Antwort in Bytes. */
    public const HEAD_BYTES = 256;

    /** User-Agent jedes Abrufs; SetupHandlers prüft bei solchen Anfragen nicht noch einmal (keine Rekursion). */
    public const USER_AGENT = 'tokenlore-setup';

    /**
     * @param string $address eigene Serveradresse (IP); alles andere ergibt nie einen Abruf
     * @param int $port eigener Port
     * @param bool $tls mit TLS verbinden (der Server hört auf https)
     * @param float $timeout Obergrenze in Sekunden für Verbindung und Antwort zusammen
     */
    public function __construct(
        private readonly string $address,
        private readonly int $port,
        private readonly bool $tls,
        private readonly float $timeout = 5.0,
    ) {
    }

    /**
     * Abrufer für die eigene Anfrage: SERVER_ADDR und SERVER_PORT, bei unbrauchbaren Angaben 127.0.0.1 und der
     * Standardport (80, bei https 443). https heißt hier: der Server selbst sprach https (nicht ein Proxy davor).
     */
    public static function forRequest(Request $r): self
    {
        $address = filter_var($r->serverAddr, FILTER_VALIDATE_IP) !== false ? $r->serverAddr : '127.0.0.1';
        $port = $r->serverPort >= 1 && $r->serverPort <= 65535 ? $r->serverPort : ($r->https ? 443 : 80);
        return new self($address, $port, $r->https);
    }

    public function address(): string
    {
        return $this->address;
    }

    public function port(): int
    {
        return $this->port;
    }

    public function tls(): bool
    {
        return $this->tls;
    }

    /**
     * Ruft Pfad und Abfrage der URL bei der eigenen Serveradresse ab (Host aus der URL nur als Host-Header).
     * null, wenn nicht abgerufen wurde oder werden durfte (ungeeignete URL, fremder Port, keine gültige eigene
     * Adresse, Verbindungsfehler, Zeitüberschreitung, keine lesbare Antwort).
     *
     * @param array<string,string> $headers zusätzliche Header (etwa Authorization für die Prüfung, ob er bei PHP
     *        ankommt); Name als Token, Wert nur druckbares ASCII, Host und die festen Header nicht überschreibbar
     * @return array{status:int, head:string}|null Statuscode und erste Bytes des Inhalts
     */
    public function __invoke(string $url, array $headers = []): ?array
    {
        if (preg_match('/^[\x21-\x7E]+\z/', $url) !== 1) {
            return null;
        }
        $extra = '';
        foreach ($headers as $name => $value) {
            if (preg_match('/^[A-Za-z0-9-]+\z/', (string) $name) !== 1 || preg_match('/^[\x20-\x7E]*\z/', $value) !== 1
                || in_array(strtolower((string) $name), ['host', 'user-agent', 'accept', 'connection'], true)) {
                return null;
            }
            $extra .= $name . ': ' . $value . "\r\n";
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            return null;
        }
        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return null;
        }
        // Der Port der URL geht nur in den Host-Header; zugelassen sind der eigene Port und die Standardports.
        if (isset($parts['port']) && !in_array($parts['port'], [$this->port, 80, 443], true)) {
            return null;
        }
        if (filter_var($this->address, FILTER_VALIDATE_IP) === false || $this->port < 1 || $this->port > 65535) {
            return null;
        }
        $path = ($parts['path'] ?? '') === '' ? '/' : $parts['path'];
        if (isset($parts['query'])) {
            $path .= '?' . $parts['query'];
        }
        $request = 'GET ' . $path . " HTTP/1.0\r\n"
            . 'Host: ' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') . "\r\n"
            . 'User-Agent: ' . self::USER_AGENT . "\r\nAccept: */*\r\nConnection: close\r\n" . $extra . "\r\n";
        $target = ($this->tls ? 'ssl://' : 'tcp://') . (str_contains($this->address, ':') ? '[' . $this->address . ']' : $this->address) . ':' . $this->port;
        return $this->exchange($target, trim($parts['host'], '[]'), $request);
    }

    /** @return array{status:int, head:string}|null */
    private function exchange(string $target, string $sniName, string $request): ?array
    {
        $deadline = microtime(true) + $this->timeout;
        $context = stream_context_create(['ssl' => [
            'peer_name' => $sniName,
            'SNI_enabled' => true,
            'SNI_server_name' => $sniName,
            'verify_peer' => false,
            'verify_peer_name' => false,
        ]]);
        // @: Fehlschläge (Verbindung verweigert, Zeitüberschreitung) sind hier der Normalfall, der Rückgabewert genügt.
        $stream = @stream_socket_client($target, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);
        if ($stream === false) {
            return null;
        }
        try {
            if (@fwrite($stream, $request) === false) {
                return null;
            }
            $buffer = '';
            while (microtime(true) < $deadline && strlen($buffer) < 16384) {
                $remaining = max(0.01, min(1.0, $deadline - microtime(true)));
                stream_set_timeout($stream, (int) $remaining, (int) (($remaining - (int) $remaining) * 1_000_000));
                $chunk = @fread($stream, 8192);
                if ($chunk === false || ($chunk === '' && feof($stream))) {
                    break;
                }
                $buffer .= $chunk;
                $end = strpos($buffer, "\r\n\r\n");
                if ($end !== false && strlen($buffer) - $end - 4 >= self::HEAD_BYTES) {
                    break;
                }
            }
        } finally {
            fclose($stream);
        }
        $end = strpos($buffer, "\r\n\r\n");
        if ($end === false || preg_match('#^HTTP/\d(?:\.\d)?[ \t]+(\d{3})#', $buffer, $m) !== 1) {
            return null;
        }
        return ['status' => (int) $m[1], 'head' => substr($buffer, $end + 4, self::HEAD_BYTES)];
    }
}
