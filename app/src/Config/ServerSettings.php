<?php

declare(strict_types=1);

namespace Tokenlore\Config;

use PDO;
use Tokenlore\Db\Database;

// Serverweite Einstellungen aus der Tabelle server_settings (nur Admins ändern sie):
// public_url (öffentliche Adresse), trust_proxy ('0' | '1') und ca_pem (eigenes CA-Zertifikat für --ca); dazu die
// unveränderliche server_id (nur lesbar).
// Eine Instanz liest die Tabelle einmal beim Laden und führt sich bei save() nach.
final class ServerSettings
{
    /** Obergrenze für das hochgeladene Zertifikat (wie maxCAFile in cafp.go). */
    private const MAX_CA_BYTES = 64 * 1024;

    private const HOST = '(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])';

    /** @param array<string,string> $values */
    private function __construct(private readonly Database $db, private array $values)
    {
    }

    public static function load(Database $db): self
    {
        $values = [];
        foreach ($db->pdo()->query('select key, value from server_settings') as $row) {
            $values[(string) $row['key']] = (string) $row['value'];
        }
        return new self($db, $values);
    }

    /** Hinterlegte öffentliche Adresse ohne Schrägstrich am Ende; null: die Adresse wird aus der Anfrage erkannt. */
    public function publicUrl(): ?string
    {
        $v = $this->values['public_url'] ?? '';
        return $v === '' ? null : $v;
    }

    /**
     * Kennung dieses Servers (64 Hex-Zeichen, klein). Sie entsteht beim Anlegen der Datenbank und ist unveränderlich:
     * save() kennt den Schlüssel nicht, Trigger der Datenbank verbieten Ändern und Löschen.
     */
    public function serverId(): string
    {
        $id = $this->values['server_id'] ?? '';
        if (preg_match('/^[0-9a-f]{64}\z/', $id) !== 1) {
            throw new \RuntimeException('server_id fehlt oder ist ungültig');
        }
        return $id;
    }

    public function trustProxy(): bool
    {
        return ($this->values['trust_proxy'] ?? '0') === '1';
    }

    /**
     * Das hochgeladene CA-Zertifikat als PEM (nur der neu kodierte erste CERTIFICATE-Block); null ohne
     * Zertifikat oder wenn die gespeicherte Zeile unbrauchbar ist (dann liefert der Server nichts aus).
     */
    public function caPem(): ?string
    {
        $stored = $this->values['ca_pem'] ?? null;
        return $stored === null ? null : (self::parseCa($stored)['pem'] ?? null);
    }

    /** SHA-256 über das DER des Zertifikats als „AB:CD:…“ (Großbuchstaben); leer ohne Zertifikat. */
    public function caFingerprint(): string
    {
        $stored = $this->values['ca_pem'] ?? null;
        $ca = $stored === null ? null : self::parseCa($stored);
        return $ca === null ? '' : self::fingerprint($ca['der']);
    }

    /**
     * Speichert die genannten Einstellungen (alles oder nichts). Schlüssel:
     * public_url (string; leer oder null entfernt), trust_proxy (bool), ca_pem (string; leer oder null entfernt).
     * Ungültige Werte werfen einen SettingError (deutscher Text und Feldname), ohne etwas zu ändern.
     *
     * @param array<string,mixed> $changes
     */
    public function save(array $changes): void
    {
        /** @var array<string,string> $set */
        $set = [];
        /** @var list<string> $remove */
        $remove = [];
        foreach ($changes as $key => $value) {
            switch ($key) {
                case 'public_url':
                    $url = self::optionalString($value, 'public_url');
                    if ($url === null) {
                        $remove[] = $key;
                    } elseif (!self::validPublicUrl($url)) {
                        throw new SettingError('Adresse ungültig (erwartet: https://host[:port][/pfad], ohne Abfrage)', $key);
                    } else {
                        $set[$key] = rtrim($url, '/');
                    }
                    break;
                case 'trust_proxy':
                    if (!is_bool($value)) {
                        throw new SettingError('Einstellung ungültig: trust_proxy', $key);
                    }
                    $set[$key] = $value ? '1' : '0';
                    break;
                case 'ca_pem':
                    $pem = self::optionalString($value, 'ca_pem');
                    if ($pem === null) {
                        $remove[] = $key;
                    } else {
                        $ca = self::parseCa($pem);
                        if ($ca === null) {
                            throw new SettingError('Zertifikat ungültig (erwartet: PEM mit einem X.509-Zertifikat, höchstens 64 KiB)', $key);
                        }
                        $set[$key] = $ca['pem'];
                    }
                    break;
                default:
                    throw new SettingError('Unbekannte Einstellung: ' . $key, (string) $key);
            }
        }
        $this->db->tx(static function (PDO $pdo) use ($set, $remove): void {
            $upsert = $pdo->prepare('insert into server_settings (key, value) values (?, ?) on conflict(key) do update set value = excluded.value');
            foreach ($set as $key => $value) {
                $upsert->execute([$key, $value]);
            }
            $delete = $pdo->prepare('delete from server_settings where key = ?');
            foreach ($remove as $key) {
                $delete->execute([$key]);
            }
        });
        foreach ($set as $key => $value) {
            $this->values[$key] = $value;
        }
        foreach ($remove as $key) {
            unset($this->values[$key]);
        }
    }

    /**
     * Prüft die öffentliche Adresse: https, Host (Name oder IP, optional Port), Pfad erlaubt (ohne . und ..),
     * kein Benutzerteil, keine Abfrage, kein Fragment, keine Leer-, Steuer-, Format-, Prozent- oder Backslash-Zeichen.
     */
    public static function validPublicUrl(string $url): bool
    {
        if (preg_match('/[\s\p{Cc}\p{Cf}\\\\?#%]/u', $url) !== 0) {
            return false;
        }
        if (!preg_match('#^https://(' . self::HOST . ')(?::([0-9]{1,5}))?((?:/[A-Za-z0-9._~-]+)*/?)\z#', $url, $m)) {
            return false;
        }
        if ($m[1][0] === '[' && filter_var(substr($m[1], 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return false;
        }
        if (($m[2] ?? '') !== '' && ((int) $m[2] < 1 || (int) $m[2] > 65535)) {
            return false;
        }
        return !in_array('.', explode('/', $m[3] ?? ''), true) && !in_array('..', explode('/', $m[3] ?? ''), true);
    }

    /** Leer oder null: null (entfernen); sonst der getrimmte Text. Andere Typen sind ungültig. */
    private static function optionalString(mixed $value, string $key): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!is_string($value)) {
            throw new SettingError('Einstellung ungültig: ' . $key, $key);
        }
        $value = trim($value);
        return $value === '' ? null : $value;
    }

    /**
     * Liest den ersten CERTIFICATE-Block (wie readCACert in cafp.go): andere Blöcke, etwa ein
     * versehentlich mitgelegter Schlüssel, werden übersprungen und nie zurückgegeben; Kopfzeilen im Block
     * entfallen. Ist der erste CERTIFICATE-Block kein gültiges X.509-Zertifikat, gilt alles als ungültig.
     *
     * @return array{pem:string, der:string}|null PEM neu kodiert (64 Zeichen je Zeile)
     */
    private static function parseCa(string $pem): ?array
    {
        if (strlen($pem) > self::MAX_CA_BYTES) {
            return null;
        }
        if (preg_match_all('/-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)\r?\n?-----END \1-----/s', $pem, $blocks, PREG_SET_ORDER) < 1) {
            return null;
        }
        foreach ($blocks as [, $type, $body]) {
            if ($type !== 'CERTIFICATE') {
                continue;
            }
            $der = self::decodeBody($body);
            if ($der === null) {
                return null;
            }
            $out = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
            // Ein unbrauchbares Zertifikat meldet openssl_x509_read als Warnung; hier ist das ein normaler Fall.
            set_error_handler(static fn(): bool => true);
            try {
                $cert = openssl_x509_read($out);
            } finally {
                restore_error_handler();
            }
            while (openssl_error_string() !== false) {
                // Fehlerwarteschlange leeren, damit spätere OpenSSL-Aufrufe sie nicht erben.
            }
            return $cert === false ? null : ['pem' => $out, 'der' => $der];
        }
        return null;
    }

    private static function decodeBody(string $body): ?string
    {
        $lines = preg_split('/\r?\n/', trim($body)) ?: [];
        $i = 0;
        while ($i < count($lines) && str_contains($lines[$i], ':')) {
            $i++;
        }
        if ($i > 0 && ($lines[$i] ?? null) === '') {
            $i++;
        }
        $b64 = preg_replace('/\s+/', '', implode('', array_slice($lines, $i))) ?? '';
        $der = base64_decode($b64, true);
        return $der === false || $der === '' ? null : $der;
    }

    private static function fingerprint(string $der): string
    {
        return strtoupper(implode(':', str_split(hash('sha256', $der), 2)));
    }
}
