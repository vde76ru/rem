<?php
namespace App\Commands;

use App\Core\Cache;
use App\Core\Logger;

/**
 * Команда для очистки кеша
 * Запуск: php src/Commands/ClearCacheCommand.php
 */
class ClearCacheCommand
{
    public function run(): void
    {
        echo "🧹 Очистка кеша...\n";
        
        try {
            // Получаем статистику до очистки
            $statsBefore = Cache::getStats();
            echo "📊 До очистки:\n";
            echo "  - Всего файлов: " . ($statsBefore['total_files'] ?? 0) . "\n";
            echo "  - Валидных файлов: " . ($statsBefore['valid_files'] ?? 0) . "\n";
            echo "  - Размер: " . $this->formatBytes($statsBefore['total_size'] ?? 0) . "\n\n";
            
            // Очищаем устаревшие файлы
            Cache::cleanup();
            
            // Если нужно очистить весь кеш
            if (in_array('--all', $_SERVER['argv'] ?? [])) {
                echo "🗑️  Полная очистка кеша...\n";
                Cache::clear();
            }
            
            // Получаем статистику после очистки
            $statsAfter = Cache::getStats();
            echo "\n📊 После очистки:\n";
            echo "  - Всего файлов: " . ($statsAfter['total_files'] ?? 0) . "\n";
            echo "  - Валидных файлов: " . ($statsAfter['valid_files'] ?? 0) . "\n";
            echo "  - Размер: " . $this->formatBytes($statsAfter['total_size'] ?? 0) . "\n";
            
            $filesRemoved = ($statsBefore['total_files'] ?? 0) - ($statsAfter['total_files'] ?? 0);
            $spaceFreed = ($statsBefore['total_size'] ?? 0) - ($statsAfter['total_size'] ?? 0);
            
            echo "\n✅ Очистка завершена!\n";
            echo "  - Удалено файлов: " . $filesRemoved . "\n";
            echo "  - Освобождено места: " . $this->formatBytes($spaceFreed) . "\n";
            
            Logger::info('Cache cleanup completed', [
                'files_removed' => $filesRemoved,
                'space_freed' => $spaceFreed
            ]);
            
        } catch (\Exception $e) {
            echo "❌ Ошибка: " . $e->getMessage() . "\n";
            Logger::error('Cache cleanup failed', ['error' => $e->getMessage()]);
        }
    }
    
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

// Запуск команды если вызвана напрямую
if (php_sapi_name() === 'cli' && realpath($argv[0]) === __FILE__) {
    require_once __DIR__ . '/../../vendor/autoload.php';
    
    // Инициализация
    \App\Core\Bootstrap::init();
    
    // Запуск очистки
    $command = new ClearCacheCommand();
    $command->run();
}