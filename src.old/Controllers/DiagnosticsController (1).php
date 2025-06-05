<?php
namespace App\Controllers;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Cache;
use App\Services\AuthService;
use OpenSearch\ClientBuilder;

class DiagnosticsController extends BaseController
{
    private array $diagnostics = [];
    private float $startTime;

    public function __construct()
    {
        $this->startTime = microtime(true);
    }

    /**
     * GET /api/admin/diagnostics/run - Запустить диагностику
     */
    public function runAction(): void
    {
        // Устанавливаем правильные заголовки для API
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');

        try {
            // Запускаем ТОЛЬКО базовые проверки (без ошибок)
            $this->checkSystem();
            $this->checkPHP();
            $this->checkDatabase();
            $this->checkCache();
            $this->checkSessions();

            // Подсчитываем health score
            $healthScore = $this->calculateHealthScore();

            // Формируем итоговый отчет
            $report = [
                'timestamp' => date('c'),
                'health_score' => $healthScore,
                'execution_time' => microtime(true) - $this->startTime,
                'diagnostics' => $this->diagnostics
            ];

            $this->success($report);

        } catch (\Exception $e) {
            Logger::error('Diagnostics failed', ['error' => $e->getMessage()]);
            $this->error('Diagnostics failed: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Проверка системы
     */
    private function checkSystem(): void
    {
        $data = [
            'title' => '🖥️ Информация о системе',
            'status' => '✅ OK',
            'data' => [
                'PHP Version' => PHP_VERSION,
                'Server Time' => date('Y-m-d H:i:s'),
                'Timezone' => date_default_timezone_get(),
                'OS' => php_uname('s') . ' ' . php_uname('r'),
                'Memory Usage' => $this->formatBytes(memory_get_usage(true)),
                'Peak Memory' => $this->formatBytes(memory_get_peak_usage(true))
            ]
        ];
        $this->diagnostics['system'] = $data;
    }

    /**
     * Проверка PHP
     */
    private function checkPHP(): void
    {
        $data = [
            'title' => '🐘 PHP Конфигурация', 
            'status' => '✅ OK',
            'checks' => [
                'Version' => PHP_VERSION,
                'Memory Limit' => ini_get('memory_limit'),
                'Max Execution Time' => ini_get('max_execution_time'),
                'Display Errors' => ini_get('display_errors') ? 'ON' : 'OFF',
                'Error Reporting' => error_reporting()
            ],
            'extensions' => [
                'PDO' => extension_loaded('pdo'),
                'MySQL' => extension_loaded('pdo_mysql'), 
                'JSON' => extension_loaded('json'),
                'cURL' => extension_loaded('curl'),
                'Session' => extension_loaded('session')
            ]
        ];
        $this->diagnostics['php'] = $data;
    }

    /**
     * Проверка базы данных
     */
    private function checkDatabase(): void
    {
        $data = [
            'title' => '🗄️ База данных',
            'status' => '❌ Error'
        ];

        try {
            $pdo = Database::getConnection();
            
            // Основная информация
            $version = $pdo->query("SELECT VERSION()")->fetchColumn();
            $data['info']['Version'] = $version;
            
            // Проверяем подключение
            $dbName = $pdo->query("SELECT DATABASE()")->fetchColumn();
            $data['info']['Database'] = $dbName;
            
            // Проверяем базовые таблицы
            $requiredTables = ['products', 'users', 'carts', 'sessions'];
            $missingTables = [];
            
            foreach ($requiredTables as $table) {
                $stmt = $pdo->prepare("SHOW TABLES LIKE ?");
                $stmt->execute([$table]);
                if (!$stmt->fetch()) {
                    $missingTables[] = $table;
                }
            }
            
            $data['info']['Missing Tables'] = empty($missingTables) ? 'None' : implode(', ', $missingTables);
            $data['status'] = empty($missingTables) ? '✅ Connected' : '⚠️ Warning';
            
        } catch (\Exception $e) {
            $data['status'] = '❌ Error';
            $data['error'] = $e->getMessage();
        }

        $this->diagnostics['database'] = $data;
    }

    /**
     * Проверка кеша
     */
    private function checkCache(): void
    {
        $data = [
            'title' => '⚡ Кеш система',
            'status' => '❌ Error'
        ];

        try {
            // Тест записи/чтения
            $testKey = 'diagnostic_test_' . time();
            $testValue = 'test_value_' . uniqid();
            
            Cache::set($testKey, $testValue, 60);
            $readValue = Cache::get($testKey);
            Cache::delete($testKey);
            
            $data['status'] = ($readValue === $testValue) ? '✅ Working' : '❌ Not Working';
            $data['info'] = Cache::getStats();
            
        } catch (\Exception $e) {
            $data['error'] = $e->getMessage();
        }

        $this->diagnostics['cache'] = $data;
    }

    /**
     * Проверка сессий
     */
    private function checkSessions(): void
    {
        $data = [
            'title' => '🔐 Сессии',
            'status' => session_status() === PHP_SESSION_ACTIVE ? '✅ Active' : '❌ Inactive',
            'data' => [
                'Handler' => ini_get('session.save_handler'),
                'Save Path' => ini_get('session.save_path'),
                'Session ID' => session_id() ?: 'None',
                'GC Lifetime' => ini_get('session.gc_maxlifetime') . ' seconds'
            ]
        ];

        // Количество сессий в БД
        try {
            $count = Database::query("SELECT COUNT(*) FROM sessions")->fetchColumn();
            $data['data']['Sessions in DB'] = $count;
        } catch (\Exception $e) {
            $data['data']['Sessions in DB'] = 'Error: ' . $e->getMessage();
        }

        $this->diagnostics['sessions'] = $data;
    }

    /**
     * Подсчет общего health score
     */
    private function calculateHealthScore(): float
    {
        $totalChecks = 0;
        $passedChecks = 0;

        foreach ($this->diagnostics as $section) {
            $totalChecks++;
            if (isset($section['status']) && strpos($section['status'], '✅') !== false) {
                $passedChecks++;
            } elseif (isset($section['status']) && strpos($section['status'], '⚠️') !== false) {
                $passedChecks += 0.5;
            }
        }

        return $totalChecks > 0 ? round(($passedChecks / $totalChecks) * 100, 2) : 0;
    }

    /**
     * Форматирование байтов
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}