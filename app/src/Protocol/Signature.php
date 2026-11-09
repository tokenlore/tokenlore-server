<?php

declare(strict_types=1);

namespace Tokenlore\Protocol;

// Signatur einer Zeile im Archiv des Plugins (Abschnitt „Hülle“ in protocol/doc.md): Ed25519 über
// "tokenlore-archiv-v1\n" + die Bytes der Inhaltszeile z, getrennt, 64 Byte, als Base64 übertragen.
// Geprüft wird über genau den gelieferten Text z; es gibt keine nachgebaute Byte-Form.
final class Signature
{
    /** Vorsatz vor der Inhaltszeile, damit eine Signatur nie für etwas anderes gilt. */
    public const PREFIX = "tokenlore-archiv-v1\n";

    /**
     * Vorsatz des Besitznachweises beim Koppeln (sign_public_key_proof): signiert wird dieser Vorsatz, die server_id,
     * ein Zeilenumbruch und der Kopplungscode (6 Ziffern), mit dem geheimen Teil von sign_public_key.
     */
    public const PAIR_PREFIX = "tokenlore-pair-v2\n";

    /** Länge der Signatur als Base64 mit Auffüllung (64 Byte). */
    public const BASE64_LEN = 88;

    /**
     * Liest eine Signatur: Base64 im Standardalphabet mit Auffüllung, genau 88 Zeichen, 64 Byte. Nur die kanonische
     * Form gilt (kodiert wieder genau zum gelieferten Text).
     *
     * @return string|null die 64 Byte roh; null, wenn ungültig
     */
    public static function decode(string $s): ?string
    {
        if (strlen($s) !== self::BASE64_LEN) {
            return null;
        }
        $raw = base64_decode($s, true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES || base64_encode($raw) !== $s) {
            return null;
        }
        return $raw;
    }

    /**
     * Index des ersten Schlüssels in $keys, zu dem die Signatur $sig (64 Byte roh) über $z passt; null, wenn keiner passt.
     *
     * @param list<string> $keys öffentliche Schlüssel, je 32 Byte roh, in der Reihenfolge, in der geprüft wird
     */
    public static function matchingKey(string $z, string $sig, array $keys): ?int
    {
        $msg = self::PREFIX . $z;
        foreach ($keys as $i => $key) {
            if (strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES && sodium_crypto_sign_verify_detached($sig, $msg, $key)) {
                return $i;
            }
        }
        return null;
    }

    /**
     * Prüft den Besitznachweis beim Koppeln: $proof (Base64, 64 Byte) ist eine Signatur über
     * pairProofMessage($serverId, $code) mit dem Schlüssel $key (32 Byte roh). Ein Nachweis gilt nur für diesen Server
     * und diesen einen Code; ein auf einem anderen Server mitgelesener gilt hier nicht. Meldet ein falscher Server die
     * server_id dieses Servers, signiert das Plugin für ihn einen hier gültigen Nachweis (Fund Z7).
     */
    public static function verifyPairProof(string $serverId, string $code, string $proof, string $key): bool
    {
        $sig = self::decode($proof);
        return $sig !== null && strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && sodium_crypto_sign_verify_detached($sig, self::pairProofMessage($serverId, $code), $key);
    }

    /** Die Bytes, über die der Besitznachweis signiert ist: PAIR_PREFIX, server_id, Zeilenumbruch, Code. */
    public static function pairProofMessage(string $serverId, string $code): string
    {
        return self::PAIR_PREFIX . $serverId . "\n" . $code;
    }
}
