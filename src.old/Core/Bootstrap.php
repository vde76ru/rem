<?php
namespace App\Core;

/**
 * Единая точка инициализации приложения
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
            
            // 3. Инициализируем обработку ошибок
            self::initializeErrorHandling();
            
            // 4. Инициализируем пути
            Paths::init();
            
            // 5. Инициализируем кеш (не требует БД)
            Cache::init();
            
            // 6. Запускаем сессию (может использовать БД)
            Session::start();
            
            // 7. Инициализируем логгер (после сессии)
            Logger::initialize();
            
            // 8. Устанавливаем заголовки безопасности
            SecurityHeaders::set();
            
            self::$initialized = true;
            
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
        ini_set('error_log', Env::get('LOG_PATH', '/var/log/php') . '/error.log');
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
            error_log(sprintf(
                "Uncaught %s: %s in %s:%d",
                get_class($e),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            ));
            
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
}