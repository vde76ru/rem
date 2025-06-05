<?php
namespace App\Core;

/**
 * Унифицированный менеджер сессий
 * Исправлены проблемы с инициализацией и обработкой ошибок
 */
class Session
{
    private static bool $started = false;
    private static bool $useDbHandler = false;
    
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
        $lifetime = (int)Env::get('SESSION_LIFETIME', 1800);
        
        session_set_cookie_params([
            'lifetime' => $lifetime,
            'path' => '/',
            'domain' => '',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        
        session_name(Env::get('SESSION_NAME', 'VDE_SESSION'));

        // Настройка обработчика
        self::setupSessionHandler();

        // Запуск сессии с обработкой ошибок
        $started = @session_start();
        
        if (!$started) {
            // Fallback на файловый handler если не удалось запустить
            self::setupFileHandler();
            $started = @session_start();
            
            if (!$started) {
                throw new \RuntimeException("Failed to start session");
            }
        }

        self::$started = true;
        self::validateSession();
    }
    
    private static function setupSessionHandler(): void
    {
        $handler = Env::get('SESSION_HANDLER', 'files');
        
        if ($handler === 'db') {
            try {
                // Проверяем доступность БД
                $pdo = Database::getConnection();
                
                // Проверяем существование таблицы sessions
                $stmt = $pdo->query("SHOW TABLES LIKE 'sessions'");
                if ($stmt->fetch()) {
                    $lifetime = (int)Env::get('SESSION_LIFETIME', 1800);
                    $dbHandler = new DBSessionHandler($pdo, $lifetime);
                    session_set_save_handler($dbHandler, true);
                    self::$useDbHandler = true;
                    return;
                }
            } catch (\Exception $e) {
                // Логируем только если Logger доступен
                if (class_exists(Logger::class)) {
                    Logger::warning("DB session handler failed, using files", [
                        'error' => $e->getMessage()
                    ]);
                }
            }
        }
        
        // Fallback на файловый handler
        self::setupFileHandler();
    }

    private static function setupFileHandler(): void
    {
        // Пробуем несколько путей для сессий
        $paths = [
            Env::get('SESSION_PATH', ''),
            '/var/www/www-root/data/mod-tmp',
            '/tmp/vdestor_sessions',
            sys_get_temp_dir()
        ];
        
        foreach ($paths as $path) {
            if (empty($path)) continue;
            
            // Создаем директорию если не существует
            if (!is_dir($path)) {
                @mkdir($path, 0700, true);
            }
            
            if (is_dir($path) && is_writable($path)) {
                ini_set('session.save_handler', 'files');
                ini_set('session.save_path', $path);
                return;
            }
        }
        
        // Используем системную временную директорию как последний вариант
        ini_set('session.save_handler', 'files');
        ini_set('session.save_path', sys_get_temp_dir());
    }

    private static function validateSession(): void
    {
        $now = time();
        
        // Проверка fingerprint для защиты от session hijacking
        $fingerprint = self::generateFingerprint();
        if (!isset($_SESSION['_fingerprint'])) {
            $_SESSION['_fingerprint'] = $fingerprint;
        } elseif ($_SESSION['_fingerprint'] !== $fingerprint) {
            // Fingerprint изменился - возможная атака
            if (class_exists(Logger::class)) {
                Logger::security('Session fingerprint mismatch', [
                    'old' => $_SESSION['_fingerprint'],
                    'new' => $fingerprint,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? ''
                ]);
            }
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
            @session_regenerate_id(true);
            $_SESSION['_regenerated'] = $now;
        }
    }

    private static function generateFingerprint(): string
    {
        $data = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            // Используем первые 3 октета IP для учета динамических IP
            substr($_SERVER['REMOTE_ADDR'] ?? '', 0, strrpos($_SERVER['REMOTE_ADDR'] ?? '', '.') ?: 0)
        ];
        
        return hash('sha256', implode('|', $data));
    }

    /**
     * Проверить, запущена ли сессия
     */
    public static function isActive(): bool
    {
        return session_status() === PHP_SESSION_ACTIVE;
    }

    /**
     * Получить значение из сессии
     */
    public static function get(string $key, $default = null)
    {
        self::ensureStarted();
        return $_SESSION[$key] ?? $default;
    }

    /**
     * Установить значение в сессии
     */
    public static function set(string $key, $value): void
    {
        self::ensureStarted();
        $_SESSION[$key] = $value;
    }

    /**
     * Проверить существование ключа
     */
    public static function has(string $key): bool
    {
        self::ensureStarted();
        return isset($_SESSION[$key]);
    }

    /**
     * Удалить значение из сессии
     */
    public static function remove(string $key): void
    {
        self::ensureStarted();
        unset($_SESSION[$key]);
    }

    /**
     * Получить все данные сессии
     */
    public static function all(): array
    {
        self::ensureStarted();
        // Исключаем служебные ключи
        $data = $_SESSION;
        unset($data['_fingerprint'], $data['_last_activity'], $data['_regenerated']);
        return $data;
    }

    /**
     * Очистить все данные сессии (кроме служебных)
     */
    public static function clear(): void
    {
        self::ensureStarted();
        $fingerprint = $_SESSION['_fingerprint'] ?? null;
        $lastActivity = $_SESSION['_last_activity'] ?? null;
        $regenerated = $_SESSION['_regenerated'] ?? null;
        
        $_SESSION = [];
        
        if ($fingerprint) $_SESSION['_fingerprint'] = $fingerprint;
        if ($lastActivity) $_SESSION['_last_activity'] = $lastActivity;
        if ($regenerated) $_SESSION['_regenerated'] = $regenerated;
    }

    /**
     * Уничтожить сессию полностью
     */
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
            
            @session_destroy();
        }
        
        self::$started = false;
    }

    /**
     * Гарантировать, что сессия запущена
     */
    private static function ensureStarted(): void
    {
        if (!self::$started && session_status() !== PHP_SESSION_ACTIVE) {
            self::start();
        }
    }

    /**
     * Регенерировать ID сессии
     */
    public static function regenerate(): void
    {
        self::ensureStarted();
        @session_regenerate_id(true);
        $_SESSION['_regenerated'] = time();
    }
}