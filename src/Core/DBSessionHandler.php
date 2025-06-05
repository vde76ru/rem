<?php
namespace App\Core;

use SessionHandlerInterface;
use PDO;

/**
 * Обработчик сессий через БД
 * Исправлено: убрано прямое логирование для избежания циклических зависимостей
 */
class DBSessionHandler implements SessionHandlerInterface
{
    private PDO $pdo;
    private int $lifetime;
    private bool $debug;

    public function __construct(PDO $pdo, int $lifetime)
    {
        $this->pdo = $pdo;
        $this->lifetime = $lifetime;
        $this->debug = Env::get('SESSION_DEBUG', 'false') === 'true';
    }

    public function open($savePath, $sessionName): bool
    {
        return true;
    }

    public function close(): bool
    {
        // Запускаем сборку мусора с вероятностью 1%
        if (mt_rand(1, 100) === 1) {
            $this->gc($this->lifetime);
        }
        return true;
    }

    public function read($sessionId): string
    {
        if ($this->debug) {
            error_log("[DBSession] Reading session: {$sessionId}");
        }
        
        try {
            $stmt = $this->pdo->prepare(
                "SELECT data FROM sessions 
                 WHERE session_id = :sid AND expires_at > NOW() 
                 LIMIT 1"
            );
            $stmt->execute(['sid' => $sessionId]);
            $data = $stmt->fetchColumn();
            
            if ($this->debug) {
                $length = $data ? strlen($data) : 0;
                error_log("[DBSession] Read {$length} bytes for session: {$sessionId}");
            }
            
            return $data !== false ? $data : '';
            
        } catch (\Exception $e) {
            error_log("[DBSession] Read error: " . $e->getMessage());
            return '';
        }
    }

    public function write($sessionId, $data): bool
    {
        if ($this->debug) {
            error_log("[DBSession] Writing " . strlen($data) . " bytes to session: {$sessionId}");
        }
        
        try {
            $expires = date('Y-m-d H:i:s', time() + $this->lifetime);
            
            // Используем INSERT ... ON DUPLICATE KEY UPDATE для атомарности
            $stmt = $this->pdo->prepare("
                INSERT INTO sessions (session_id, data, created_at, expires_at, ip_address, user_agent)
                VALUES (:sid, :data, NOW(), :expires, :ip, :ua)
                ON DUPLICATE KEY UPDATE
                    data = VALUES(data),
                    expires_at = VALUES(expires_at),
                    ip_address = VALUES(ip_address),
                    user_agent = VALUES(user_agent),
                    last_activity = NOW()
            ");
            
            $result = $stmt->execute([
                'sid' => $sessionId,
                'data' => $data,
                'expires' => $expires,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                'ua' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)
            ]);
            
            if ($this->debug) {
                error_log("[DBSession] Write " . ($result ? 'successful' : 'failed') . " for session: {$sessionId}");
            }
            
            return $result;
            
        } catch (\Exception $e) {
            error_log("[DBSession] Write error: " . $e->getMessage());
            return false;
        }
    }

    public function destroy($sessionId): bool
    {
        if ($this->debug) {
            error_log("[DBSession] Destroying session: {$sessionId}");
        }
        
        try {
            $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE session_id = :sid");
            $result = $stmt->execute(['sid' => $sessionId]);
            
            if ($this->debug && $result) {
                error_log("[DBSession] Destroyed session: {$sessionId}, rows affected: " . $stmt->rowCount());
            }
            
            return $result;
            
        } catch (\Exception $e) {
            error_log("[DBSession] Destroy error: " . $e->getMessage());
            return false;
        }
    }

    public function gc($maxlifetime): int|false
    {
        try {
            // Удаляем истекшие сессии
            $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE expires_at < NOW()");
            $stmt->execute();
            $deleted = $stmt->rowCount();
            
            if ($this->debug && $deleted > 0) {
                error_log("[DBSession] Garbage collection: removed {$deleted} expired sessions");
            }
            
            // Опционально: удаляем очень старые сессии (старше 7 дней)
            $stmt = $this->pdo->prepare("DELETE FROM sessions WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
            $stmt->execute();
            $oldDeleted = $stmt->rowCount();
            
            if ($this->debug && $oldDeleted > 0) {
                error_log("[DBSession] Garbage collection: removed {$oldDeleted} old sessions");
            }
            
            return $deleted + $oldDeleted;
            
        } catch (\Exception $e) {
            error_log("[DBSession] GC error: " . $e->getMessage());
            return false;
        }
    }
}