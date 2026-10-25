<?php

declare(strict_types=1);

namespace Tokenlore\Accounts;

use Tokenlore\Db\Database;
use Tokenlore\Util\Names;
use Tokenlore\Util\Sql;

// Konten: Anzeigenamen (wie Rename in internal/accounts; Prüfung mit Util\Names wie names.Clean).
final class Accounts
{
    public function __construct(private readonly Database $db)
    {
    }

    /** Setzt den Anzeigenamen eines Kontos; ein leerer Name (nur Leerraum) entfernt ihn. */
    public function rename(int $uid, string $accountId, string $name): void
    {
        $name = Names::trimSpace($name) === '' ? '' : (Names::clean($name) ?? throw AccountError::invalid());
        $st = Sql::run($this->db->pdo(), "update accounts set display_name = nullif(?, '') where user_id = ? and account_id = ?",
            [$name, $uid, $accountId]);
        if ($st->rowCount() === 0) {
            throw AccountError::notFound();
        }
    }
}
