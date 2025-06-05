<?php
namespace App\Core;

/**
 * Единая точка инициализации приложения
 * Исправлен порядок инициализации для избежания циклических зависимостей
 */
class Bootstrap
{
    private static bool $initialized = false;
    
    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }

        try {
            // 1. Загружаем переменные окружения
            Env::load();
            
            // 2. Базовые настройки PHP
            self::configurePHP();
            
            // 3. Инициализируем обработку ошибок (до всего остального)
            self::initializeErrorHandling();
            
            // 4. Инициализируем пути
            Paths::init();
            
            // 5. Инициализируем кеш (самостоятельный, без зависимостей)
            Cache::init();
            
            // 6. Инициализируем простой файловый логгер (без БД)
            Logger::initialize();
            
            // 7. Проверяем доступность БД (опционально)
            self::checkDatabase();
            
            // 8. Запускаем сессию (после логгера)
            Session::start();
            
            // 9. Устанавливаем заголовки безопасности
            SecurityHeaders::set();
            
            self::$initialized = true;
            
            // Логируем успешную инициализацию
            Logger::info('Application initialized successfully');
            
        } catch (\Exception $e) {
            error_log("Bootstrap failed: " . $e->getMessage());
            throw $e;
        }
    }
    
    private static function configurePHP(): void
    {
        $timezone = Env::get('APP_TIMEZONE', 'Europe/Moscow');
        date_default_timezone_set($timezone);
        
        $debug = Env::get('APP_DEBUG', 'false') === 'true';
        
        if ($debug) {
            error_reporting(E_ALL);
            ini_set('display_errors', '1');
        } else {
            error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
            ini_set('display_errors', '0');
        }
        
        ini_set('log_errors', '1');
        
        // Создаем директорию для логов если не существует
        $logDir = Env::get('LOG_PATH', '/var/log/vdestor');
        if (!is_dir($logDir)) {
            @mkdir($logDir, 0755, true);
        }
        
        if (is_writable($logDir)) {
            ini_set('error_log', $logDir . '/php_errors.log');
        }
    }
    
    private static function initializeErrorHandling(): void
    {
        set_error_handler(function($severity, $message, $file, $line) {
            if (!(error_reporting() & $severity)) {
                return false;
            }
            
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });
        
        set_exception_handler(function(\Throwable $e) {
            $message = sprintf(
                "Uncaught %s: %s in %s:%d",
                get_class($e),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            );
            
            error_log($message);
            
            // Пытаемся залогировать если Logger доступен
            if (class_exists(Logger::class)) {
                try {
                    Logger::critical($message, [
                        'exception' => get_class($e),
                        'file' => $e->getFile(),
                        'line' => $e->getLine(),
                        'trace' => $e->getTraceAsString()
                    ]);
                } catch (\Exception $logError) {
                    // Игнорируем ошибки логирования
                }
            }
            
            if (Env::get('APP_DEBUG', 'false') === 'true') {
                echo "<pre>Error: " . $e->getMessage() . "\n";
                echo $e->getTraceAsString() . "</pre>";
            } else {
                http_response_code(500);
                echo "Internal Server Error";
            }
            
            exit(1);
        });
    }
    
    private static function checkDatabase(): void
    {
        try {
            // Проверяем доступность БД
            Database::getConnection();
            Logger::info('Database connection established');
        } catch (\Exception $e) {
            Logger::warning('Database not available at startup', [
                'error' => $e->getMessage()
            ]);
            // Не прерываем инициализацию - приложение может работать без БД
        }
    }
    
    public static function isInitialized(): bool
    {
        return self::$initialized;
    }
}