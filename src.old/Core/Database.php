<?php
namespace App\Core;

use PDO;
use PDOException;

/**
 * Упрощенный менеджер БД без циклических зависимостей
 */
class Database
{
    private static ?PDO $connection = null;
    private static array $stats = [
        'query_count' => 0,
        'total_time' => 0
    ];

    public static function getConnection(): PDO
    {
        if (self::$connection === null) {
            self::connect();
        }

        return self::$connection;
    }

    private static function connect(): void
    {
        $host = Env::get('DB_HOST', 'localhost');
        $port = Env::get('DB_PORT', 3306);
        $dbname = Env::get('DB_NAME');
        $user = Env::get('DB_USER');
        $password = Env::get('DB_PASSWORD');

        if (!$dbname || !$user) {
            throw new \RuntimeException('Database configuration missing');
        }

        $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

        try {
            self::$connection = new PDO($dsn, $user, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ]);
            
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new \RuntimeException("Database connection failed: " . $e->getMessage());
        }
    }

    public static function query(string $sql, array $params = []): \PDOStatement
    {
        $start = microtime(true);
        
        try {
            $pdo = self::getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            
            self::$stats['query_count']++;
            self::$stats['total_time'] += microtime(true) - $start;
            
            return $stmt;
            
        } catch (PDOException $e) {
            error_log("Query failed: " . $e->getMessage() . " SQL: " . $sql);
            throw $e;
        }
    }

    public static function getStats(): array
    {
        return array_merge(self::$stats, [
            'average_time' => self::$stats['query_count'] > 0 
                ? self::$stats['total_time'] / self::$stats['query_count'] 
                : 0
        ]);
    }
}