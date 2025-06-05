<?php
namespace App\Core;

/**
 * Простой загрузчик переменных окружения
 */
class Env
{
    private static array $variables = [];
    private static bool $loaded = false;

    public static function load(string $path = null): void
    {
        if (self::$loaded) {
            return;
        }

        $path = $path ?: '/etc/vdestor/config/.env';

        
        if (!file_exists($path)) {
            throw new \RuntimeException("Environment file not found: {$path}");
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) {
                continue;
            }

            if (strpos($line, '=') !== false) {
                [$name, $value] = explode('=', $line, 2);
                $name = trim($name);
                $value = trim($value);
                
                // Убираем кавычки
                $value = trim($value, '"\'');
                
                self::$variables[$name] = $value;
                $_ENV[$name] = $value;
                putenv("{$name}={$value}");
            }
        }

        self::$loaded = true;
    }

    public static function get(string $key, $default = null)
    {
        if (!self::$loaded) {
            self::load();
        }

        return self::$variables[$key] ?? $_ENV[$key] ?? getenv($key) ?: $default;
    }
}