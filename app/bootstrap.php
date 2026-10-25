<?php

declare(strict_types=1);

// Autoloader ohne Composer: Tokenlore\Foo\Bar liegt in app/src/Foo/Bar.php.
spl_autoload_register(static function (string $class): void {
    $prefix = 'Tokenlore\\';
    if (!str_starts_with($class, $prefix) || str_starts_with($class, 'Tokenlore\\Tests\\')) {
        return;
    }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

// Warnungen und Hinweise werden zu Ausnahmen, damit kein Fehler still durchrutscht. Hinweise auf veraltete
// Sprachmittel (E_DEPRECATED) nur ins Protokoll: eine neuere PHP-Version soll die Seite nicht lahmlegen.
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    if (($severity & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0) {
        error_log(sprintf('Veraltet: %s in %s:%d', $message, $file, $line));
        return true;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});
