<?php
namespace App\Core;

/**
 * Упрощенный логгер без циклических зависимостей
 * БД логирование происходит асинхронно через очередь
 */
class Logger
{
    private static bool $initialized = false;
    private static string $logPath;
    private static bool $useDatabase = false;
    private static bool $inDatabaseOperation = false;
    
    public static function initialize(): void
    {
        if (self::$initialized) {
            return;
        }

        self::$logPath = Env::get('LOG_PATH', '/var/log/vdestor');
        
        // Создаем директорию для логов
        if (!is_dir(self::$logPath)) {
            @mkdir(self::$logPath, 0755, true);
        }

        // Проверяем доступность директории
        if (!is_writable(self::$logPath)) {
            // Fallback на временную директорию
            self::$logPath = sys_get_temp_dir() . '/vdestor_logs';
            @mkdir(self::$logPath, 0755, true);
        }

        // БД логирование включаем только если явно указано
        self::$useDatabase = Env::get('LOG_TO_DATABASE', 'false') === 'true';

        self::$initialized = true;
    }

    public static function log(string $level, string $message, array $context = []): void
    {
        if (!self::$initialized) {
            self::initialize();
        }

        $timestamp = date('Y-m-d H:i:s');
        $logEntry = [
            'timestamp' => $timestamp,
            'level' => $level,
            'message' => $message,
            'context' => $context
        ];

        // Всегда пишем в файл
        self::logToFile($logEntry);

        // В БД только если включено и мы не в процессе БД операции
        if (self::$useDatabase && !self::$inDatabaseOperation) {
            self::queueDatabaseLog($logEntry);
        }
    }

    private static function logToFile(array $entry): void
    {
        $filename = self::$logPath . '/app.log';
        
        // Ротация логов если файл слишком большой (10MB)
        if (file_exists($filename) && filesize($filename) > 10485760) {
            @rename($filename, $filename . '.' . date('Y-m-d-His'));
        }
        
        $line = sprintf(
            "[%s] %s: %s %s\n",
            $entry['timestamp'],
            strtoupper($entry['level']),
            $entry['message'],
            !empty($entry['context']) ? json_encode($entry['context'], JSON_UNESCAPED_UNICODE) : ''
        );
        
        @file_put_contents($filename, $line, FILE_APPEND | LOCK_EX);
    }

    private static function queueDatabaseLog(array $entry): void
    {
        // Вместо прямой записи в БД, добавляем в очередь
        // Это предотвращает циклические зависимости
        $queueFile = self::$logPath . '/db_queue.log';
        
        $queueEntry = [
            'timestamp' => $entry['timestamp'],
            'level' => $entry['level'],
            'message' => $entry['message'],
            'context' => json_encode($entry['context'], JSON_UNESCAPED_UNICODE)
        ];
        
        $line = json_encode($queueEntry, JSON_UNESCAPED_UNICODE) . "\n";
        @file_put_contents($queueFile, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Обработать очередь логов для БД
     * Вызывается из cron или воркера
     */
    public static function processQueuedLogs(): int
    {
        $queueFile = self::$logPath . '/db_queue.log';
        if (!file_exists($queueFile)) {
            return 0;
        }

        $tempFile = $queueFile . '.processing';
        if (!@rename($queueFile, $tempFile)) {
            return 0;
        }

        self::$inDatabaseOperation = true;
        $processed = 0;

        try {
            $pdo = Database::getConnection();
            $stmt = $pdo->prepare(
                "INSERT INTO application_logs (level, message, context, created_at) 
                 VALUES (:level, :message, :context, :created_at)"
            );

            $lines = file($tempFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            foreach ($lines as $line) {
                $entry = json_decode($line, true);
                if (!$entry) continue;

                try {
                    $stmt->execute($entry);
                    $processed++;
                } catch (\Exception $e) {
                    // Игнорируем ошибки отдельных записей
                }
            }

            @unlink($tempFile);
            
        } catch (\Exception $e) {
            // Возвращаем файл обратно если не удалось обработать
            @rename($tempFile, $queueFile);
            error_log("Failed to process log queue: " . $e->getMessage());
        } finally {
            self::$inDatabaseOperation = false;
        }

        return $processed;
    }

    // Методы-обертки для разных уровней
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
        if (Env::get('LOG_DEBUG', 'false') === 'true') {
            self::log('debug', $message, $context);
        }
    }

    public static function security(string $message, array $context = []): void
    {
        $context['security_event'] = true;
        $context['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $context['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        self::log('security', "[SECURITY] {$message}", $context);
    }

    /**
     * Очистка старых логов
     */
    public static function cleanup(int $daysToKeep = 30): int
    {
        $deleted = 0;
        
        // Очистка файловых логов
        $files = glob(self::$logPath . '/*.log.*');
        if ($files) {
            $cutoff = time() - ($daysToKeep * 86400);
            foreach ($files as $file) {
                if (filemtime($file) < $cutoff) {
                    if (@unlink($file)) {
                        $deleted++;
                    }
                }
            }
        }

        // Очистка БД логов (если используется)
        if (self::$useDatabase) {
            try {
                self::$inDatabaseOperation = true;
                $pdo = Database::getConnection();
                $stmt = $pdo->prepare(
                    "DELETE FROM application_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL :days DAY)"
                );
                $stmt->execute(['days' => $daysToKeep]);
                $deleted += $stmt->rowCount();
            } catch (\Exception $e) {
                error_log("Failed to cleanup database logs: " . $e->getMessage());
            } finally {
                self::$inDatabaseOperation = false;
            }
        }

        return $deleted;
    }

    /**
     * Получить путь к логам
     */
    public static function getLogPath(): string
    {
        return self::$logPath;
    }
}