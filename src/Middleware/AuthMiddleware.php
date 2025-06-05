<?php
namespace App\Middleware;

use App\Services\AuthService;
use App\Core\Logger;

/**
 * Единый middleware для проверки аутентификации
 */
class AuthMiddleware
{
    public static function handle(): bool
    {
        if (!AuthService::check()) {
            self::handleUnauthorized();
            return false;
        }
        
        return true;
    }

    public static function requireRole(string $role): bool
    {
        if (!self::handle()) {
            return false;
        }

        $user = AuthService::user();
        
        if (!$user || !self::hasRole($user, $role)) {
            self::handleForbidden($role);
            return false;
        }

        return true;
    }

    private static function hasRole(array $user, string $requiredRole): bool
    {
        $userRole = $user['role'] ?? '';
        
        // Админ имеет доступ ко всему
        if ($userRole === 'admin') {
            return true;
        }
        
        return $userRole === $requiredRole;
    }

    private static function handleUnauthorized(): void
    {
        Logger::security("Unauthorized access attempt", [
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? ''
        ]);

        if (self::isAjax()) {
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'error' => 'Authentication required',
                'redirect' => '/login'
            ]);
        } else {
            header('Location: /login');
        }
        
        exit;
    }

    private static function handleForbidden(string $requiredRole): void
    {
        $user = AuthService::user();
        
        Logger::security("Access denied", [
            'required_role' => $requiredRole,
            'user_role' => $user['role'] ?? 'none',
            'user_id' => $user['id'] ?? null,
            'uri' => $_SERVER['REQUEST_URI'] ?? ''
        ]);

        if (self::isAjax()) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode([
                'success' => false,
                'error' => 'Insufficient permissions'
            ]);
        } else {
            http_response_code(403);
            echo "Access denied";
        }
        
        exit;
    }

    private static function isAjax(): bool
    {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }
}