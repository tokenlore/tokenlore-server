<?php

declare(strict_types=1);

namespace Tokenlore\Config;

use RuntimeException;

// Wo der Server seine Dateien ablegt: Installationsordner und Datenordner.
// Der Datenordner ist standardmäßig <install>/data; eine Datei <install>/config.local.php mit
// `return ['data_dir' => '/pfad'];` verlegt ihn (z. B. außerhalb des Webroots).
final class Paths
{
    private function __construct(
        private readonly string $installDir,
        private readonly string $dataDir,
    ) {
    }

    public static function fromInstallDir(string $installDir): self
    {
        $install = self::trimSeparator($installDir);
        $data = $install . '/data';

        $local = $install . '/config.local.php';
        if (is_file($local)) {
            $config = require $local;
            if (!is_array($config)) {
                throw new RuntimeException('config.local.php muss ein Array zurückgeben.');
            }
            if (array_key_exists('data_dir', $config)) {
                if (!is_string($config['data_dir']) || trim($config['data_dir']) === '') {
                    throw new RuntimeException('data_dir in config.local.php muss ein nichtleerer Pfad sein.');
                }
                $dir = self::trimSeparator($config['data_dir']);
                // Relative Angaben gelten ab dem Installationsordner, nicht ab dem Arbeitsordner des Prozesses.
                $data = self::isAbsolute($dir) ? $dir : $install . '/' . $dir;
            }
        }

        return new self($install, $data);
    }

    public function installDir(): string
    {
        return $this->installDir;
    }

    public function dataDir(): string
    {
        return $this->dataDir;
    }

    // Die eine Datenbankdatei tokenlore-*.sqlite im Datenordner; null, wenn es keine gibt.
    public function databaseFile(): ?string
    {
        if (!is_dir($this->dataDir)) {
            return null;
        }
        $found = [];
        foreach (scandir($this->dataDir) ?: [] as $name) {
            if (preg_match('/^tokenlore-.+\.sqlite$/', $name) === 1 && is_file($this->dataDir . '/' . $name)) {
                $found[] = $name;
            }
        }
        if (count($found) > 1) {
            throw new RuntimeException(
                'Im Datenordner liegt mehr als eine Datenbank (' . implode(', ', $found) . '). Es darf nur eine geben.'
            );
        }
        return $found === [] ? null : $this->dataDir . '/' . $found[0];
    }

    // Pfad für eine neue Datenbank. Der Zufallsanteil macht den Namen unratbar, falls der
    // Datenordner doch einmal über das Web erreichbar wäre.
    public function newDatabaseFile(): string
    {
        return $this->dataDir . '/tokenlore-' . bin2hex(random_bytes(16)) . '.sqlite';
    }

    private static function trimSeparator(string $path): string
    {
        $trimmed = rtrim($path, '/\\');
        return $trimmed === '' ? $path : $trimmed;
    }

    private static function isAbsolute(string $path): bool
    {
        return $path[0] === '/' || $path[0] === '\\' || preg_match('/^[A-Za-z]:[\/\\\\]/', $path) === 1;
    }
}
