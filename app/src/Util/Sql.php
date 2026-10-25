<?php

declare(strict_types=1);

namespace Tokenlore\Util;

use PDO;
use PDOStatement;

// Kurzform für Abfragen mit Parametern.
final class Sql
{
    /**
     * Führt eine Abfrage mit Parametern aus; ganze Zahlen werden als Zahl gebunden (nicht als Text),
     * damit Vergleiche und Rechnungen in SQLite ohne Umwandlung laufen.
     *
     * @param list<int|string|null> $args
     */
    public static function run(PDO $pdo, string $sql, array $args = []): PDOStatement
    {
        $st = $pdo->prepare($sql);
        foreach (array_values($args) as $i => $v) {
            $st->bindValue($i + 1, $v, match (true) {
                is_int($v) => PDO::PARAM_INT,
                $v === null => PDO::PARAM_NULL,
                default => PDO::PARAM_STR,
            });
        }
        $st->execute();
        return $st;
    }
}
