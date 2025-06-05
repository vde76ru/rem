<?php
namespace App\Services;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Session;
use App\Core\Cache;
use App\Core\CSRF;
use App\Services\CartService;
use App\Exceptions\AuthenticationException;

/**
 * Полностью переработанный сервис аутентификации
 * с улучшенной безопасностью и интеграцией Session API
 */
class AuthService
{
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOCKOUT_DURATION = 900; // 15 минут
    const SESSION_LIFETIME = 3600; // 1 час
    const REMEMBER_ME_DURATION = 2592000; // 30 дней
    const PASSWORD_MIN_LENGTH = 8;
    const USER_CACHE_TTL = 300; // 5 минут
    
    /**
     * Аутентифицировать пользователя с полной проверкой
     */
    public static function authenticate(string $login, string $password, bool $remember = false): array
    {
        try {
            // Базовая валидация
            if (empty($login) || empty($password)) {
                return self::failedAuth('Введите логин и пароль');
            }
            
            // Нормализуем логин
            $login = self::normalizeLogin($login);
            
            // Проверяем блокировку по IP и логину
            $lockKey = self::getLockKey($login);
            if (self::isBlocked($lockKey)) {
                $remainingTime = self::getRemainingLockTime($lockKey);
                return self::failedAuth("Аккаунт временно заблокирован. Попробуйте через {$remainingTime} минут");
            }
            
            // Находим пользователя
            $user = self::findUserByLogin($login);
            if (!$user) {
                self::recordFailedAttempt($lockKey, $login);
                return self::failedAuth('Неверный логин или пароль');
            }
            
            // Проверяем пароль с защитой от timing attack
            if (!self::verifyPassword($password, $user['password_hash'])) {
                self::recordFailedAttempt($lockKey, $login);
                return self::failedAuth('Неверный логин или пароль');
            }
            
            // Проверяем активность аккаунта
            if (!$user['is_active']) {
                return self::failedAuth('Аккаунт деактивирован');
            }
            
            // Проверяем подтверждение email (если требуется)
            if (self::requiresEmailVerification() && !$user['email_verified_at']) {
                return self::failedAuth('Необходимо подтвердить email адрес');
            }
            
            // Успешная аутентификация
            self::clearFailedAttempts($lockKey);
            
            // Создаем сессию
            $sessionData = self::createAuthSession($user, $remember);
            
            // Логируем успешный вход
            self::logSuccessfulLogin($user['user_id']);
            
            // Объединяем гостевую корзину
            self::mergeGuestData($user['user_id']);
            
            return [
                'success' => true,
                'user' => self::sanitizeUserData($user),
                'session' => $sessionData,
                'redirect' => self::getPostLoginRedirect($user)
            ];
            
        } catch (\Exception $e) {
            Logger::error('Authentication error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return self::failedAuth('Ошибка системы аутентификации');
        }
    }
    
    /**
     * Проверить текущую сессию
     */
    public static function check(): bool
    {
        if (!Session::isActive()) {
            return false;
        }
        
        // Проверяем наличие данных аутентификации
        if (!Session::has('auth_user_id') || !Session::has('auth_session_id')) {
            return false;
        }
        
        // Проверяем валидность сессии
        if (!self::validateAuthSession()) {
            self::logout();
            return false;
        }
        
        // Обновляем активность
        Session::set('auth_last_activity', time());
        
        return true;
    }
    
    /**
     * Получить текущего пользователя
     */
    public static function user(): ?array
    {
        if (!self::check()) {
            return null;
        }
        
        $userId = Session::get('auth_user_id');
        
        // Проверяем кеш
        $cacheKey = 'user:' . $userId;
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return $cached;
        }
        
        // Загружаем из БД
        $user = self::loadUser($userId);
        
        if ($user) {
            // Кешируем
            Cache::set($cacheKey, $user, self::USER_CACHE_TTL);
        }
        
        return $user;
    }
    
    /**
     * Проверить роль пользователя
     */
    public static function checkRole(string $role): bool
    {
        $user = self::user();
        if (!$user) {
            return false;
        }
        
        // Админ имеет все роли
        if ($user['role'] === 'admin') {
            return true;
        }
        
        return $user['role'] === $role;
    }
    
    /**
     * Проверить права доступа
     */
    public static function can(string $permission): bool
    {
        $user = self::user();
        if (!$user) {
            return false;
        }
        
        // Админ может всё
        if ($user['role'] === 'admin') {
            return true;
        }
        
        // Загружаем права роли
        $permissions = self::getRolePermissions($user['role_id']);
        
        return in_array($permission, $permissions);
    }
    
    /**
     * Выйти из системы
     */
    public static function logout(): void
    {
        $userId = Session::get('auth_user_id');
        
        if ($userId) {
            // Логируем выход
            self::logLogout($userId);
            
            // Инвалидируем кеш
            Cache::delete('user:' . $userId);
            
            // Удаляем remember me токен
            self::clearRememberToken($userId);
        }
        
        // Очищаем данные аутентификации
        self::clearAuthSession();
        
        // Инвалидируем CSRF токены
        CSRF::invalidateAll();
        
        // Регенерируем сессию
        Session::regenerate();
    }
    
    /**
     * Уничтожить сессию полностью
     */
    public static function destroySession(): void
    {
        self::logout();
        Session::destroy();
    }
    
    /**
     * Валидировать сессию
     */
    public static function validateSession(): bool
    {
        return self::check();
    }
    
    // === Управление паролями ===
    
    /**
     * Хешировать пароль
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    /**
     * Проверить требования к паролю
     */
    public static function validatePasswordStrength(string $password): array
    {
        $errors = [];
        
        if (strlen($password) < self::PASSWORD_MIN_LENGTH) {
            $errors[] = 'Пароль должен содержать минимум ' . self::PASSWORD_MIN_LENGTH . ' символов';
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Пароль должен содержать строчные буквы';
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Пароль должен содержать заглавные буквы';
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Пароль должен содержать цифры';
        }
        
        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = 'Пароль должен содержать специальные символы';
        }
        
        return $errors;
    }
    
    // === Remember Me функциональность ===
    
    /**
     * Проверить remember me токен
     */
    public static function checkRememberToken(): ?array
    {
        if (!isset($_COOKIE['remember_token'])) {
            return null;
        }
        
        $token = $_COOKIE['remember_token'];
        
        try {
            // Декодируем токен
            $parts = explode(':', $token);
            if (count($parts) !== 2) {
                return null;
            }
            
            [$userId, $tokenHash] = $parts;
            
            // Проверяем в БД
            $stmt = Database::query(
                "SELECT u.*, r.name as role_name, rt.expires_at 
                 FROM users u
                 JOIN roles r ON u.role_id = r.role_id
                 LEFT JOIN remember_tokens rt ON rt.user_id = u.user_id
                 WHERE u.user_id = ? AND rt.token_hash = ? AND rt.expires_at > NOW()
                 AND u.is_active = 1",
                [$userId, $tokenHash]
            );
            
            $user = $stmt->fetch();
            
            if ($user) {
                // Обновляем токен
                self::refreshRememberToken($userId);
                
                // Создаем сессию
                self::createAuthSession($user, true);
                
                return self::sanitizeUserData($user);
            }
            
        } catch (\Exception $e) {
            Logger::error('Remember token validation failed', [
                'error' => $e->getMessage()
            ]);
        }
        
        // Удаляем невалидный токен
        self::clearRememberCookie();
        
        return null;
    }
    
    // === Приватные методы ===
    
    /**
     * Найти пользователя по логину
     */
    private static function findUserByLogin(string $login): ?array
    {
        $stmt = Database::query(
            "SELECT u.*, r.name as role_name 
             FROM users u 
             JOIN roles r ON u.role_id = r.role_id 
             WHERE (LOWER(u.username) = LOWER(?) OR LOWER(u.email) = LOWER(?))
             LIMIT 1",
            [$login, $login]
        );
        
        return $stmt->fetch() ?: null;
    }
    
    /**
     * Загрузить пользователя по ID
     */
    private static function loadUser(int $userId): ?array
    {
        $stmt = Database::query(
            "SELECT u.*, r.name as role_name, r.role_id,
                    up.first_name, up.last_name, up.phone,
                    c.name as city_name, c.city_id
             FROM users u 
             JOIN roles r ON u.role_id = r.role_id
             LEFT JOIN user_profiles up ON u.user_id = up.user_id
             LEFT JOIN cities c ON u.city_id = c.city_id
             WHERE u.user_id = ? AND u.is_active = 1",
            [$userId]
        );
        
        $user = $stmt->fetch();
        
        return $user ? self::sanitizeUserData($user) : null;
    }
    
    /**
     * Проверить пароль безопасно
     */
    private static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
    
    /**
     * Создать сессию аутентификации
     */
    private static function createAuthSession(array $user, bool $remember = false): array
    {
        // Регенерируем ID сессии для безопасности
        Session::regenerate();
        
        // Генерируем уникальный ID сессии
        $sessionId = bin2hex(random_bytes(32));
        
        // Сохраняем данные аутентификации
        Session::set('auth_user_id', $user['user_id']);
        Session::set('auth_session_id', $sessionId);
        Session::set('auth_role', $user['role_name']);
        Session::set('auth_created_at', time());
        Session::set('auth_last_activity', time());
        Session::set('auth_ip', $_SERVER['REMOTE_ADDR'] ?? '');
        Session::set('auth_user_agent', $_SERVER['HTTP_USER_AGENT'] ?? '');
        
        // Обновляем последний вход
        Database::query(
            "UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE user_id = ?",
            [$_SERVER['REMOTE_ADDR'] ?? '', $user['user_id']]
        );
        
        // Создаем remember me токен если нужно
        if ($remember) {
            self::createRememberToken($user['user_id']);
        }
        
        return [
            'session_id' => $sessionId,
            'expires_at' => time() + self::SESSION_LIFETIME
        ];
    }
    
    /**
     * Валидировать текущую сессию аутентификации
     */
    private static function validateAuthSession(): bool
    {
        // Проверяем время жизни сессии
        $createdAt = Session::get('auth_created_at', 0);
        if ((time() - $createdAt) > self::SESSION_LIFETIME) {
            return false;
        }
        
        // Проверяем неактивность
        $lastActivity = Session::get('auth_last_activity', 0);
        if ((time() - $lastActivity) > Config::get('session.idle_timeout', 1800)) {
            return false;
        }
        
        // Проверяем соответствие окружения
        if (Config::get('auth.check_ip', true)) {
            $sessionIp = Session::get('auth_ip');
            if ($sessionIp !== ($_SERVER['REMOTE_ADDR'] ?? '')) {
                Logger::security('IP mismatch in auth session', [
                    'session_ip' => $sessionIp,
                    'current_ip' => $_SERVER['REMOTE_ADDR'] ?? ''
                ]);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Очистить данные аутентификации из сессии
     */
    private static function clearAuthSession(): void
    {
        $authKeys = [
            'auth_user_id',
            'auth_session_id',
            'auth_role',
            'auth_created_at',
            'auth_last_activity',
            'auth_ip',
            'auth_user_agent'
        ];
        
        foreach ($authKeys as $key) {
            Session::remove($key);
        }
    }
    
    /**
     * Создать remember me токен
     */
    private static function createRememberToken(int $userId): void
    {
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $expiresAt = date('Y-m-d H:i:s', time() + self::REMEMBER_ME_DURATION);
        
        // Сохраняем в БД
        Database::query(
            "INSERT INTO remember_tokens (user_id, token_hash, expires_at, created_at)
             VALUES (?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE 
             token_hash = VALUES(token_hash),
             expires_at = VALUES(expires_at),
             created_at = NOW()",
            [$userId, $tokenHash, $expiresAt]
        );
        
        // Устанавливаем cookie
        setcookie(
            'remember_token',
            $userId . ':' . $tokenHash,
            time() + self::REMEMBER_ME_DURATION,
            '/',
            '',
            !empty($_SERVER['HTTPS']),
            true
        );
    }
    
    /**
     * Обновить remember me токен
     */
    private static function refreshRememberToken(int $userId): void
    {
        self::createRememberToken($userId);
    }
    
    /**
     * Удалить remember me токен
     */
    private static function clearRememberToken(int $userId): void
    {
        Database::query(
            "DELETE FROM remember_tokens WHERE user_id = ?",
            [$userId]
        );
        
        self::clearRememberCookie();
    }
    
    /**
     * Удалить remember me cookie
     */
    private static function clearRememberCookie(): void
    {
        if (isset($_COOKIE['remember_token'])) {
            setcookie('remember_token', '', time() - 3600, '/', '', !empty($_SERVER['HTTPS']), true);
        }
    }
    
    // === Блокировка и защита от перебора ===
    
    /**
     * Получить ключ блокировки
     */
    private static function getLockKey(string $login): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        return 'auth_lock:' . md5($login . ':' . $ip);
    }
    
    /**
     * Проверить блокировку
     */
    private static function isBlocked(string $lockKey): bool
    {
        $attempts = Cache::get($lockKey . ':attempts', 0);
        return $attempts >= self::MAX_LOGIN_ATTEMPTS;
    }
    
    /**
     * Записать неудачную попытку
     */
    private static function recordFailedAttempt(string $lockKey, string $login): void
    {
        $attempts = Cache::get($lockKey . ':attempts', 0) + 1;
        Cache::set($lockKey . ':attempts', $attempts, self::LOCKOUT_DURATION);
        
        // Логируем в БД для анализа
        Database::query(
            "INSERT INTO login_attempts (identifier, failed_attempts, last_attempt, ip_address)
             VALUES (?, 1, NOW(), ?)
             ON DUPLICATE KEY UPDATE 
             failed_attempts = failed_attempts + 1,
             last_attempt = NOW()",
            [$login, $_SERVER['REMOTE_ADDR'] ?? '']
        );
        
        Logger::security('Failed login attempt', [
            'login' => $login,
            'attempts' => $attempts,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? ''
        ]);
    }
    
    /**
     * Очистить неудачные попытки
     */
    private static function clearFailedAttempts(string $lockKey): void
    {
        Cache::delete($lockKey . ':attempts');
    }
    
    /**
     * Получить оставшееся время блокировки
     */
    private static function getRemainingLockTime(string $lockKey): int
    {
        // Здесь можно реализовать более точный расчет
        return ceil(self::LOCKOUT_DURATION / 60);
    }
    
    // === Вспомогательные методы ===
    
    /**
     * Нормализовать логин
     */
    private static function normalizeLogin(string $login): string
    {
        return trim(mb_strtolower($login));
    }
    
    /**
     * Очистить данные пользователя
     */
    private static function sanitizeUserData(array $user): array
    {
        unset(
            $user['password_hash'],
            $user['password_reset_token'],
            $user['two_factor_secret']
        );
        
        return $user;
    }
    
    /**
     * Проверить требование подтверждения email
     */
    private static function requiresEmailVerification(): bool
    {
        return Config::get('auth.require_email_verification', false);
    }
    
    /**
     * Получить URL перенаправления после входа
     */
    private static function getPostLoginRedirect(array $user): string
    {
        // Проверяем сохраненный URL
        $intendedUrl = Session::get('url.intended');
        if ($intendedUrl) {
            Session::remove('url.intended');
            return $intendedUrl;
        }
        
        // По умолчанию в зависимости от роли
        return match($user['role_name']) {
            'admin' => '/admin',
            'manager' => '/manager',
            default => '/dashboard'
        };
    }
    
    /**
     * Объединить данные гостя с пользователем
     */
    private static function mergeGuestData(int $userId): void
    {
        try {
            // Объединяем корзину
            CartService::mergeGuestCartWithUser($userId);
            
            // Здесь можно добавить объединение других данных
            // Например: избранное, сравнения и т.д.
            
        } catch (\Exception $e) {
            Logger::warning('Failed to merge guest data', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
        }
    }
    
    /**
     * Получить права роли
     */
    private static function getRolePermissions(int $roleId): array
    {
        $cacheKey = 'role_permissions:' . $roleId;
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return $cached;
        }
        
        $stmt = Database::query(
            "SELECT p.code 
             FROM permissions p
             JOIN role_permissions rp ON p.id = rp.permission_id
             WHERE rp.role_id = ?",
            [$roleId]
        );
        
        $permissions = $stmt->fetchAll(\PDO::FETCH_COLUMN);
        
        Cache::set($cacheKey, $permissions, 3600);
        
        return $permissions;
    }
    
    /**
     * Сформировать ответ об ошибке
     */
    private static function failedAuth(string $message): array
    {
        return [
            'success' => false,
            'error' => $message,
            'attempts_remaining' => null // Можно добавить расчет
        ];
    }
    
    /**
     * Логировать успешный вход
     */
    private static function logSuccessfulLogin(int $userId): void
    {
        Logger::info('Successful login', [
            'user_id' => $userId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
        
        AuditService::log($userId, 'login', 'auth', $userId, [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }
    
    /**
     * Логировать выход
     */
    private static function logLogout(int $userId): void
    {
        Logger::info('User logout', ['user_id' => $userId]);
        
        AuditService::log($userId, 'logout', 'auth', $userId, [
            'session_duration' => time() - Session::get('auth_created_at', time())
        ]);
    }
}