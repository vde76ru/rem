<?php
namespace App\Core;

/**
 * Упрощенный логгер без циклических зависимостей
 */
class Logger
{
    private static bool $initialized = false;
    private static string $logPath;
    private static bool $useDatabase = false;
    
    public static function initialize(): void
    {
        if (self::$initialized) {
            return;
        }

        self::$logPath = Env::get('LOG_PATH', '/var/log/vdestor');
        
        if (!is_dir(self::$logPath)) {
            @mkdir(self::$logPath, 0755, true);
        }

        // Включаем БД логирование только если БД доступна
        try {
            Database::getConnection();
            self::$useDatabase = true;
        } catch (\Exception $e) {
            self::$useDatabase = false;
        }

        self::$initialized = true;
    }

    public static function log(string $level, string $message, array $context = []): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = [
            'timestamp' => $timestamp,
            'level' => $level,
            'message' => $message,
            'context' => $context
        ];

        // Всегда пишем в файл
        self::logToFile($logEntry);

        // В БД только если доступна
        if (self::$useDatabase) {
            self::logToDatabase($logEntry);
        }
    }

    private static function logToFile(array $entry): void
    {
        $filename = self::$logPath . '/app.log';
        $line = sprintf(
            "[%s] %s: %s %s\n",
            $entry['timestamp'],
            strtoupper($entry['level']),
            $entry['message'],
            !empty($entry['context']) ? json_encode($entry['context']) : ''
        );
        
        @file_put_contents($filename, $line, FILE_APPEND | LOCK_EX);
    }

    private static function logToDatabase(array $entry): void
    {
        static $inDatabaseLog = false;
        
        if ($inDatabaseLog) {
            return; // Предотвращаем рекурсию
        }

        $inDatabaseLog = true;

        try {
            Database::query(
                "INSERT INTO application_logs (level, message, context, created_at) 
                 VALUES (?, ?, ?, NOW())",
                [
                    $entry['level'],
                    $entry['message'],
                    json_encode($entry['context'])
                ]
            );
        } catch (\Exception $e) {
            // Игнорируем ошибки БД логирования
        } finally {
            $inDatabaseLog = false;
        }
    }

    // Методы-обертки
    public static function emergency(string $message, array $context = []): void
    {
        self::log('emergency', $message, $context);
    }

    public static function alert(string $message, array $context = []): void
    {
        self::log('alert', $message, $context);
    }

    public static function critical(string $message, array $context = []): void
    {
        self::log('critical', $message, $context);
    }

    public static function error(string $message, array $context = []): void
    {
        self::log('error', $message, $context);
    }

    public static function warning(string $message, array $context = []): void
    {
        self::log('warning', $message, $context);
    }

    public static function notice(string $message, array $context = []): void
    {
        self::log('notice', $message, $context);
    }

    public static function info(string $message, array $context = []): void
    {
        self::log('info', $message, $context);
    }

    public static function debug(string $message, array $context = []): void
    {
        self::log('debug', $message, $context);
    }

    public static function security(string $message, array $context = []): void
    {
        $context['security_event'] = true;
        self::log('warning', "[SECURITY] {$message}", $context);
    }
}