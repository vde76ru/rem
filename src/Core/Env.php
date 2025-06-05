<?php
namespace App\Core;

/**
 * Централизованная система управления конфигурацией
 * с поддержкой окружений, кеширования и динамической загрузки
 */
class Config
{
    private static array $config = [];
    private static bool $loaded = false;
    private static string $environment = 'production';
    private static array $configPaths = [];
    private static array $cache = [];
    
    /**
     * Инициализация конфигурации
     */
    public static function init(): void
    {
        if (self::$loaded) {
            return;
        }
        
        // Определяем окружение
        self::$environment = Env::get('APP_ENV', 'production');
        
        // Определяем пути к конфигурационным файлам
        self::$configPaths = [
            'primary' => Env::get('CONFIG_PATH', '/etc/vdestor/config'),
            'secondary' => Paths::get('root') . '/config',
            'env_specific' => Paths::get('root') . '/config/' . self::$environment
        ];
        
        // Загружаем конфигурацию
        self::loadConfiguration();
        
        self::$loaded = true;
    }
    
    /**
     * Получить значение конфигурации
     */
    public static function get(string $key, $default = null)
    {
        if (!self::$loaded) {
            self::init();
        }
        
        // Проверяем кеш
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }
        
        // Парсим ключ (например: 'database.host')
        $segments = explode('.', $key);
        $value = self::$config;
        
        foreach ($segments as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                // Пробуем загрузить из БД если включено
                if (self::isDatabaseConfigEnabled()) {
                    $dbValue = self::getFromDatabase($key);
                    if ($dbValue !== null) {
                        self::$cache[$key] = $dbValue;
                        return $dbValue;
                    }
                }
                
                self::$cache[$key] = $default;
                return $default;
            }
            
            $value = $value[$segment];
        }
        
        // Обрабатываем переменные окружения в значениях
        if (is_string($value)) {
            $value = self::parseEnvironmentVariables($value);
        }
        
        self::$cache[$key] = $value;
        return $value;
    }
    
    /**
     * Установить значение конфигурации
     */
    public static function set(string $key, $value): void
    {
        if (!self::$loaded) {
            self::init();
        }
        
        $segments = explode('.', $key);
        $config = &self::$config;
        
        foreach ($segments as $i => $segment) {
            if ($i === count($segments) - 1) {
                $config[$segment] = $value;
            } else {
                if (!isset($config[$segment]) || !is_array($config[$segment])) {
                    $config[$segment] = [];
                }
                $config = &$config[$segment];
            }
        }
        
        // Очищаем кеш
        unset(self::$cache[$key]);
        
        // Сохраняем в БД если включено
        if (self::isDatabaseConfigEnabled()) {
            self::saveToDatabase($key, $value);
        }
    }
    
    /**
     * Проверить существование ключа
     */
    public static function has(string $key): bool
    {
        return self::get($key, '__not_found__') !== '__not_found__';
    }
    
    /**
     * Получить все значения конфигурации
     */
    public static function all(): array
    {
        if (!self::$loaded) {
            self::init();
        }
        
        return self::$config;
    }
    
    /**
     * Получить текущее окружение
     */
    public static function environment(): string
    {
        return self::$environment;
    }
    
    /**
     * Проверить окружение
     */
    public static function isEnvironment(string ...$environments): bool
    {
        return in_array(self::$environment, $environments);
    }
    
    /**
     * Проверить продакшен
     */
    public static function isProduction(): bool
    {
        return self::$environment === 'production';
    }
    
    /**
     * Проверить режим отладки
     */
    public static function isDebug(): bool
    {
        return self::get('app.debug', false);
    }
    
    /**
     * Перезагрузить конфигурацию
     */
    public static function reload(): void
    {
        self::$loaded = false;
        self::$config = [];
        self::$cache = [];
        self::init();
    }
    
    /**
     * Валидировать конфигурацию безопасности
     */
    public static function validateSecurity(): array
    {
        $issues = [];
        
        // Проверяем критические настройки
        if (self::isProduction()) {
            if (self::get('app.debug', false)) {
                $issues[] = 'Debug mode is enabled in production';
            }
            
            if (!self::get('app.key')) {
                $issues[] = 'Application key is not set';
            }
            
            if (self::get('database.password') === 'password') {
                $issues[] = 'Default database password is used';
            }
            
            if (!self::get('session.secure', false) && !empty($_SERVER['HTTPS'])) {
                $issues[] = 'Secure session cookies are not enabled';
            }
        }
        
        return $issues;
    }
    
    // === Приватные методы ===
    
    /**
     * Загрузить всю конфигурацию
     */
    private static function loadConfiguration(): void
    {
        // 1. Загружаем базовую конфигурацию
        self::loadDefaultConfig();
        
        // 2. Загружаем файлы конфигурации
        foreach (self::$configPaths as $type => $path) {
            if (is_dir($path)) {
                self::loadConfigDirectory($path);
            }
        }
        
        // 3. Загружаем переменные окружения
        self::loadEnvironmentOverrides();
        
        // 4. Загружаем из БД если доступно
        if (self::isDatabaseAvailable()) {
            self::loadDatabaseConfig();
        }
        
        // 5. Валидируем конфигурацию
        self::validateConfiguration();
    }
    
    /**
     * Загрузить конфигурацию по умолчанию
     */
    private static function loadDefaultConfig(): void
    {
        self::$config = [
            'app' => [
                'name' => 'VDestor B2B',
                'env' => self::$environment,
                'debug' => false,
                'url' => 'https://vdestor.ru',
                'timezone' => 'Europe/Moscow',
                'locale' => 'ru',
                'key' => Env::get('APP_KEY'),
            ],
            
            'database' => [
                'driver' => 'mysql',
                'host' => 'localhost',
                'port' => 3306,
                'database' => Env::get('DB_NAME'),
                'username' => Env::get('DB_USER'),
                'password' => Env::get('DB_PASSWORD'),
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
                'strict' => true,
                'engine' => 'InnoDB',
            ],
            
            'cache' => [
                'default' => 'file',
                'stores' => [
                    'file' => [
                        'driver' => 'file',
                        'path' => '/tmp/vdestor_cache',
                    ],
                    'redis' => [
                        'driver' => 'redis',
                        'connection' => 'cache',
                    ],
                ],
                'prefix' => 'vdestor_cache',
            ],
            
            'session' => [
                'driver' => Env::get('SESSION_DRIVER', 'file'),
                'lifetime' => 120,
                'expire_on_close' => false,
                'encrypt' => true,
                'files' => '/var/www/www-root/data/mod-tmp',
                'connection' => null,
                'table' => 'sessions',
                'store' => null,
                'lottery' => [2, 100],
                'cookie' => 'vdestor_session',
                'path' => '/',
                'domain' => null,
                'secure' => !empty($_SERVER['HTTPS']),
                'http_only' => true,
                'same_site' => 'lax',
            ],
            
            'logging' => [
                'default' => 'daily',
                'channels' => [
                    'daily' => [
                        'driver' => 'daily',
                        'path' => '/var/log/vdestor/app.log',
                        'level' => 'debug',
                        'days' => 14,
                    ],
                ],
            ],
            
            'mail' => [
                'mailer' => 'smtp',
                'host' => Env::get('MAIL_HOST', 'localhost'),
                'port' => Env::get('MAIL_PORT', 587),
                'encryption' => Env::get('MAIL_ENCRYPTION', 'tls'),
                'username' => Env::get('MAIL_USERNAME'),
                'password' => Env::get('MAIL_PASSWORD'),
                'from' => [
                    'address' => Env::get('MAIL_FROM_ADDRESS', 'noreply@vdestor.ru'),
                    'name' => Env::get('MAIL_FROM_NAME', 'VDestor B2B'),
                ],
            ],
            
            'queue' => [
                'default' => 'database',
                'connections' => [
                    'database' => [
                        'driver' => 'database',
                        'table' => 'job_queue',
                        'queue' => 'default',
                        'retry_after' => 90,
                    ],
                ],
            ],
            
            'auth' => [
                'defaults' => [
                    'guard' => 'web',
                    'passwords' => 'users',
                ],
                'guards' => [
                    'web' => [
                        'driver' => 'session',
                        'provider' => 'users',
                    ],
                    'api' => [
                        'driver' => 'token',
                        'provider' => 'users',
                    ],
                ],
                'providers' => [
                    'users' => [
                        'driver' => 'database',
                        'table' => 'users',
                    ],
                ],
                'passwords' => [
                    'users' => [
                        'provider' => 'users',
                        'table' => 'password_resets',
                        'expire' => 60,
                        'throttle' => 60,
                    ],
                ],
                'password_timeout' => 10800,
                'require_email_verification' => false,
                'check_ip' => true,
            ],
            
            'security' => [
                'csrf' => [
                    'enabled' => true,
                    'check_ip' => false,
                    'check_user_agent' => true,
                    'token_lifetime' => 3600,
                    'max_tokens' => 10,
                ],
                'rate_limiting' => [
                    'enabled' => true,
                    'max_attempts' => 60,
                    'decay_minutes' => 1,
                ],
                'cors' => [
                    'allowed_origins' => ['*'],
                    'allowed_methods' => ['*'],
                    'allowed_headers' => ['*'],
                    'exposed_headers' => [],
                    'max_age' => 0,
                    'supports_credentials' => false,
                ],
            ],
            
            'opensearch' => [
                'hosts' => [
                    [
                        'host' => 'localhost',
                        'port' => 9200,
                        'scheme' => 'http',
                    ],
                ],
                'retries' => 2,
                'timeout' => 5,
                'index_prefix' => 'vdestor_',
            ],
        ];
    }
    
    /**
     * Загрузить директорию с конфигурационными файлами
     */
    private static function loadConfigDirectory(string $path): void
    {
        $files = glob($path . '/*.php');
        
        foreach ($files as $file) {
            $name = basename($file, '.php');
            
            // Пропускаем файлы окружений
            if (in_array($name, ['local', 'testing', 'staging', 'production'])) {
                continue;
            }
            
            $config = require $file;
            
            if (is_array($config)) {
                self::$config[$name] = array_merge(
                    self::$config[$name] ?? [],
                    $config
                );
            }
        }
    }
    
    /**
     * Загрузить переопределения из переменных окружения
     */
    private static function loadEnvironmentOverrides(): void
    {
        // Маппинг переменных окружения на конфигурацию
        $mappings = [
            'APP_DEBUG' => 'app.debug',
            'APP_URL' => 'app.url',
            'DB_HOST' => 'database.host',
            'DB_PORT' => 'database.port',
            'DB_DATABASE' => 'database.database',
            'DB_USERNAME' => 'database.username',
            'DB_PASSWORD' => 'database.password',
            'CACHE_DRIVER' => 'cache.default',
            'SESSION_DRIVER' => 'session.driver',
            'MAIL_MAILER' => 'mail.mailer',
            'QUEUE_CONNECTION' => 'queue.default',
        ];
        
        foreach ($mappings as $env => $config) {
            $value = Env::get($env);
            if ($value !== null) {
                self::set($config, $value);
            }
        }
    }
    
    /**
     * Загрузить конфигурацию из БД
     */
    private static function loadDatabaseConfig(): void
    {
        try {
            $stmt = Database::query(
                "SELECT config_key, config_value FROM app_config WHERE is_sensitive = 0"
            );
            
            while ($row = $stmt->fetch()) {
                $value = json_decode($row['config_value'], true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    self::set($row['config_key'], $value);
                }
            }
        } catch (\Exception $e) {
            // БД недоступна - используем файловую конфигурацию
        }
    }
    
    /**
     * Парсить переменные окружения в строке
     */
    private static function parseEnvironmentVariables(string $value): string
    {
        return preg_replace_callback('/\${([^}]+)}/', function ($matches) {
            return Env::get($matches[1], $matches[0]);
        }, $value);
    }
    
    /**
     * Проверить доступность БД
     */
    private static function isDatabaseAvailable(): bool
    {
        try {
            Database::getConnection();
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
    
    /**
     * Проверить включена ли БД конфигурация
     */
    private static function isDatabaseConfigEnabled(): bool
    {
        return Env::get('CONFIG_USE_DATABASE', 'false') === 'true';
    }
    
    /**
     * Получить из БД
     */
    private static function getFromDatabase(string $key)
    {
        try {
            $stmt = Database::query(
                "SELECT config_value FROM app_config WHERE config_key = ? LIMIT 1",
                [$key]
            );
            
            $row = $stmt->fetch();
            if ($row) {
                $value = json_decode($row['config_value'], true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    return $value;
                }
            }
        } catch (\Exception $e) {
            // Игнорируем ошибки БД
        }
        
        return null;
    }
    
    /**
     * Сохранить в БД
     */
    private static function saveToDatabase(string $key, $value): void
    {
        try {
            $json = json_encode($value, JSON_UNESCAPED_UNICODE);
            
            Database::query(
                "INSERT INTO app_config (config_key, config_value, updated_at) 
                 VALUES (?, ?, NOW()) 
                 ON DUPLICATE KEY UPDATE 
                 config_value = VALUES(config_value), 
                 updated_at = NOW()",
                [$key, $json]
            );
        } catch (\Exception $e) {
            // Игнорируем ошибки БД
        }
    }
    
    /**
     * Валидировать конфигурацию
     */
    private static function validateConfiguration(): void
    {
        $required = [
            'app.key' => 'Application key is required',
            'database.database' => 'Database name is required',
            'database.username' => 'Database username is required',
        ];
        
        foreach ($required as $key => $message) {
            if (!self::has($key) || empty(self::get($key))) {
                throw new \RuntimeException($message);
            }
        }
    }
}