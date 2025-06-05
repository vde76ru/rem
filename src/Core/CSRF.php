<?php
namespace App\Core;

/**
 * Улучшенная система защиты от CSRF с двойной проверкой и привязкой к сессии
 */
class CSRF
{
    const TOKEN_LENGTH = 32;
    const TOKEN_LIFETIME = 3600; // 1 час
    const MAX_TOKENS = 10; // Максимум активных токенов
    const TOKEN_NAME = 'csrf_token';
    const HEADER_NAME = 'X-CSRF-Token';
    
    /**
     * Генерировать новый CSRF токен
     */
    public static function generate(): string
    {
        Session::ensureStarted();
        
        // Генерируем уникальный токен
        $token = bin2hex(random_bytes(self::TOKEN_LENGTH));
        
        // Получаем все токены из сессии
        $tokens = Session::get('csrf_tokens', []);
        
        // Удаляем истекшие токены
        $tokens = self::cleanupExpiredTokens($tokens);
        
        // Ограничиваем количество токенов
        if (count($tokens) >= self::MAX_TOKENS) {
            // Удаляем самый старый
            array_shift($tokens);
        }
        
        // Добавляем новый токен с метаданными
        $tokens[$token] = [
            'created_at' => time(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            'used' => false
        ];
        
        // Сохраняем в сессию
        Session::set('csrf_tokens', $tokens);
        
        // Также сохраняем последний токен для быстрого доступа
        Session::set('csrf_token', $token);
        
        return $token;
    }
    
    /**
     * Получить текущий токен или создать новый
     */
    public static function token(): string
    {
        Session::ensureStarted();
        
        // Проверяем последний токен
        $token = Session::get('csrf_token');
        $tokens = Session::get('csrf_tokens', []);
        
        // Если токен существует и не истек
        if ($token && isset($tokens[$token]) && !self::isTokenExpired($tokens[$token])) {
            return $token;
        }
        
        // Генерируем новый
        return self::generate();
    }
    
    /**
     * Валидировать токен с расширенными проверками
     */
    public static function validate(?string $token, bool $checkOnce = true): bool
    {
        if (empty($token)) {
            self::logFailure('empty_token');
            return false;
        }
        
        Session::ensureStarted();
        
        // Проверяем токен из заголовка если не передан явно
        if ($token === null) {
            $token = self::getTokenFromRequest();
        }
        
        $tokens = Session::get('csrf_tokens', []);
        
        // Проверяем существование токена
        if (!isset($tokens[$token])) {
            self::logFailure('token_not_found', $token);
            return false;
        }
        
        $tokenData = $tokens[$token];
        
        // Проверяем срок действия
        if (self::isTokenExpired($tokenData)) {
            self::logFailure('token_expired', $token);
            unset($tokens[$token]);
            Session::set('csrf_tokens', $tokens);
            return false;
        }
        
        // Проверяем одноразовость
        if ($checkOnce && $tokenData['used']) {
            self::logFailure('token_reused', $token);
            return false;
        }
        
        // Проверяем соответствие окружения
        if (!self::validateEnvironment($tokenData)) {
            self::logFailure('environment_mismatch', $token);
            return false;
        }
        
        // Помечаем как использованный
        if ($checkOnce) {
            $tokens[$token]['used'] = true;
            $tokens[$token]['used_at'] = time();
            Session::set('csrf_tokens', $tokens);
        }
        
        return true;
    }
    
    /**
     * Валидировать без пометки использования (для AJAX)
     */
    public static function check(string $token): bool
    {
        return self::validate($token, false);
    }
    
    /**
     * Получить HTML поле для формы
     */
    public static function field(): string
    {
        $token = self::token();
        return sprintf(
            '<input type="hidden" name="%s" value="%s" />',
            htmlspecialchars(self::TOKEN_NAME),
            htmlspecialchars($token)
        );
    }
    
    /**
     * Получить мета-тег для AJAX запросов
     */
    public static function metaTag(): string
    {
        $token = self::token();
        return sprintf(
            '<meta name="csrf-token" content="%s" />',
            htmlspecialchars($token)
        );
    }
    
    /**
     * Инвалидировать все токены (при выходе)
     */
    public static function invalidateAll(): void
    {
        Session::remove('csrf_tokens');
        Session::remove('csrf_token');
    }
    
    /**
     * Получить статистику токенов
     */
    public static function getStats(): array
    {
        Session::ensureStarted();
        
        $tokens = Session::get('csrf_tokens', []);
        $active = 0;
        $used = 0;
        $expired = 0;
        
        foreach ($tokens as $tokenData) {
            if (self::isTokenExpired($tokenData)) {
                $expired++;
            } elseif ($tokenData['used']) {
                $used++;
            } else {
                $active++;
            }
        }
        
        return [
            'total' => count($tokens),
            'active' => $active,
            'used' => $used,
            'expired' => $expired,
            'limit' => self::MAX_TOKENS
        ];
    }
    
    // === Приватные методы ===
    
    /**
     * Получить токен из запроса
     */
    private static function getTokenFromRequest(): ?string
    {
        // 1. Проверяем POST данные
        if (isset($_POST[self::TOKEN_NAME])) {
            return $_POST[self::TOKEN_NAME];
        }
        
        // 2. Проверяем заголовки
        $headers = getallheaders();
        if (isset($headers[self::HEADER_NAME])) {
            return $headers[self::HEADER_NAME];
        }
        
        // 3. Проверяем X-Requested-With для AJAX
        if (isset($headers['X-Requested-With']) && $headers['X-Requested-With'] === 'XMLHttpRequest') {
            // Для AJAX может быть в других местах
            if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
                return $_SERVER['HTTP_X_CSRF_TOKEN'];
            }
        }
        
        return null;
    }
    
    /**
     * Проверить истечение токена
     */
    private static function isTokenExpired(array $tokenData): bool
    {
        return (time() - $tokenData['created_at']) > self::TOKEN_LIFETIME;
    }
    
    /**
     * Очистить истекшие токены
     */
    private static function cleanupExpiredTokens(array $tokens): array
    {
        $cleaned = [];
        
        foreach ($tokens as $token => $data) {
            if (!self::isTokenExpired($data)) {
                $cleaned[$token] = $data;
            }
        }
        
        return $cleaned;
    }
    
    /**
     * Валидировать окружение запроса
     */
    private static function validateEnvironment(array $tokenData): bool
    {
        // Проверяем IP (только для высокого уровня безопасности)
        if (Config::get('csrf.check_ip', false)) {
            $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
            if ($tokenData['ip'] !== $currentIp) {
                return false;
            }
        }
        
        // Проверяем User-Agent (опционально)
        if (Config::get('csrf.check_user_agent', true)) {
            $currentUA = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            if ($tokenData['user_agent'] !== $currentUA) {
                // Логируем но не блокируем (UA может меняться)
                Logger::warning('CSRF User-Agent mismatch', [
                    'original' => $tokenData['user_agent'],
                    'current' => $currentUA
                ]);
            }
        }
        
        return true;
    }
    
    /**
     * Логировать неудачную проверку
     */
    private static function logFailure(string $reason, ?string $token = null): void
    {
        Logger::security('CSRF validation failed', [
            'reason' => $reason,
            'token' => $token ? substr($token, 0, 8) . '...' : null,
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
        
        // Увеличиваем счетчик для rate limiting
        if (class_exists(RateLimiter::class)) {
            RateLimiter::hit('csrf_failures:' . ($_SERVER['REMOTE_ADDR'] ?? ''));
        }
    }
}