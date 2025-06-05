<?php
namespace App\Core;

/**
 * Централизованное управление путями
 */
class Paths
{
    private static array $paths = [];
    private static bool $initialized = false;

    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }

        $root = dirname(__DIR__, 2);
        
        self::$paths = [
            'root' => $root,
            'public' => $root . '/public',
            'src' => $root . '/src',
            'views' => $root . '/src/views',
            'config' => Env::get('CONFIG_PATH', '/etc/vdestor/config'),
            'logs' => Env::get('LOG_PATH', '/var/log/vdestor'),
            'cache' => Env::get('CACHE_PATH', '/tmp/vdestor_cache'),
            'sessions' => '/var/www/www-root/data/mod-tmp',
            'uploads' => $root . '/public/uploads',
            'assets' => $root . '/public/assets'
        ];

        self::$initialized = true;
    }

    public static function get(string $key, string $append = ''): string
    {
        if (!self::$initialized) {
            self::init();
        }

        if (!isset(self::$paths[$key])) {
            throw new \InvalidArgumentException("Unknown path key: {$key}");
        }

        $path = self::$paths[$key];
        
        if ($append) {
            $path .= '/' . ltrim($append, '/');
        }

        return $path;
    }

    public static function exists(string $key, string $append = ''): bool
    {
        try {
            return file_exists(self::get($key, $append));
        } catch (\Exception $e) {
            return false;
        }
    }

    public static function url(string $path): string
    {
        return '/' . ltrim($path, '/');
    }

    public static function asset(string $path): string
    {
        return '/assets/dist/' . ltrim($path, '/');
    }
}