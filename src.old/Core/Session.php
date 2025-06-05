<?php
namespace App\Core;

/**
 * Унифицированный менеджер сессий
 */
class Session
{
    private static bool $started = false;
    
    public static function start(): void
    {
        if (self::$started || session_status() === PHP_SESSION_ACTIVE) {
            self::$started = true;
            return;
        }

        if (headers_sent($file, $line)) {
            throw new \RuntimeException("Cannot start session, headers sent in {$file}:{$line}");
        }

        // Настройки сессии
        $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        
        session_set_cookie_params([
            'lifetime' => (int)Env::get('SESSION_LIFETIME', 1800),
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        
        session_name(Env::get('SESSION_NAME', 'VDE_SESSION'));

        // Настройка обработчика
        $handler = Env::get('SESSION_HANDLER', 'files');
        
        if ($handler === 'db') {
            try {
                $pdo = Database::getConnection();
                $dbHandler = new DBSessionHandler($pdo, (int)Env::get('SESSION_LIFETIME', 1800));
                session_set_save_handler($dbHandler, true);
            } catch (\Exception $e) {
                error_log("DB session handler failed, using files: " . $e->getMessage());
                self::setupFileHandler();
            }
        } else {
            self::setupFileHandler();
        }

        // Запуск сессии
        if (!session_start()) {
            throw new \RuntimeException("Failed to start session");
        }

        self::$started = true;
        self::validateSession();
    }

    private static function setupFileHandler(): void
    {
        $path = '/var/www/www-root/data/mod-tmp';
        if (!is_dir($path) || !is_writable($path)) {
            $path = sys_get_temp_dir();
        }
        
        ini_set('session.save_handler', 'files');
        ini_set('session.save_path', $path);
    }

    private static function validateSession(): void
    {
        $now = time();
        
        // Проверка fingerprint
        $fingerprint = self::generateFingerprint();
        if (!isset($_SESSION['_fingerprint'])) {
            $_SESSION['_fingerprint'] = $fingerprint;
        } elseif ($_SESSION['_fingerprint'] !== $fingerprint) {
            self::destroy();
            self::start();
            return;
        }

        // Проверка времени жизни
        if (isset($_SESSION['_last_activity'])) {
            $maxLifetime = (int)Env::get('SESSION_LIFETIME', 1800);
            if ($now - $_SESSION['_last_activity'] > $maxLifetime) {
                self::destroy();
                self::start();
                return;
            }
        }
        $_SESSION['_last_activity'] = $now;

        // Регенерация ID каждые 30 минут
        if (!isset($_SESSION['_regenerated'])) {
            $_SESSION['_regenerated'] = $now;
        } elseif ($now - $_SESSION['_regenerated'] > 1800) {
            session_regenerate_id(true);
            $_SESSION['_regenerated'] = $now;
        }
    }

    private static function generateFingerprint(): string
    {
        $data = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            substr($_SERVER['REMOTE_ADDR'] ?? '', 0, strrpos($_SERVER['REMOTE_ADDR'] ?? '', '.'))
        ];
        
        return hash('sha256', implode('|', $data));
    }

    public static function get(string $key, $default = null)
    {
        return $_SESSION[$key] ?? $default;
    }

    public static function set(string $key, $value): void
    {
        $_SESSION[$key] = $value;
    }

    public static function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    public static function destroy(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            
            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                setcookie(
                    session_name(),
                    '',
                    time() - 42000,
                    $params['path'],
                    $params['domain'],
                    $params['secure'],
                    $params['httponly']
                );
            }
            
            session_destroy();
        }
        
        self::$started = false;
    }

    public static function isActive(): bool
    {
        return session_status() === PHP_SESSION_ACTIVE;
    }
}