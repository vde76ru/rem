<?php
namespace App\Services;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Session;
use App\Core\Cache;
use App\Exceptions\CartException;

/**
 * Полностью переработанный сервис корзины с идеальной интеграцией Session API
 * и оптимизированной работой с кешем
 */
class CartService
{
    const SESSION_KEY = 'cart';
    const CACHE_PREFIX = 'cart:';
    const CACHE_TTL = 1800; // 30 минут
    const MAX_ITEMS = 100;
    const MAX_QUANTITY = 9999;
    const MERGE_LOCK_KEY = 'cart_merge:';
    const MERGE_LOCK_TTL = 30;
    
    /**
     * Получить корзину с интеллектуальным кешированием
     */
    public static function get(?int $userId = null): array
    {
        try {
            // Определяем источник данных
            if ($userId > 0) {
                return self::getUserCart($userId);
            } else {
                return self::getGuestCart();
            }
        } catch (\Exception $e) {
            Logger::error('Cart loading error', [
                'user_id' => $userId,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return [];
        }
    }
    
    /**
     * Получить корзину авторизованного пользователя с кешированием
     */
    private static function getUserCart(int $userId): array
    {
        // Проверяем кеш
        $cacheKey = self::CACHE_PREFIX . 'user:' . $userId;
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return $cached;
        }
        
        // Загружаем из БД
        $cart = self::loadFromDatabase($userId);
        
        // Кешируем результат
        Cache::set($cacheKey, $cart, self::CACHE_TTL);
        
        return $cart;
    }
    
    /**
     * Получить гостевую корзину
     */
    private static function getGuestCart(): array
    {
        Session::ensureStarted();
        
        $sessionId = session_id();
        if (!$sessionId) {
            return [];
        }
        
        // Проверяем кеш для гостевой корзины
        $cacheKey = self::CACHE_PREFIX . 'guest:' . $sessionId;
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return $cached;
        }
        
        // Загружаем из сессии
        $cart = Session::get(self::SESSION_KEY, []);
        
        // Валидируем структуру корзины
        $cart = self::validateCartStructure($cart);
        
        // Кешируем
        Cache::set($cacheKey, $cart, self::CACHE_TTL);
        
        return $cart;
    }
    
    /**
     * Добавить товар в корзину с полной проверкой
     */
    public static function add(int $productId, int $quantity = 1, ?int $userId = null): array
    {
        // Базовая валидация
        self::validateAddRequest($productId, $quantity);
        
        // Получаем информацию о товаре с кешированием
        $product = self::getProductInfoCached($productId);
        if (!$product) {
            throw new CartException('Товар не найден');
        }
        
        // Проверяем бизнес-правила
        self::validateBusinessRules($product, $quantity);
        
        // Получаем текущую корзину
        $cart = self::get($userId);
        
        // Проверяем лимиты корзины
        self::validateCartLimits($cart, $productId);
        
        // Получаем город и проверяем наличие
        $cityId = self::getCurrentCityId();
        $stock = self::getProductStockCached($productId, $cityId);
        
        if ($stock <= 0) {
            throw new CartException('Товар отсутствует на складе');
        }
        
        // Рассчитываем новое количество
        $currentQuantity = $cart[$productId]['quantity'] ?? 0;
        $newQuantity = $currentQuantity + $quantity;
        
        // Проверяем доступность
        self::validateAvailability($product, $newQuantity, $stock);
        
        // Обновляем корзину
        $cart = self::updateCartItem($cart, $productId, $newQuantity, $cityId);
        
        // Сохраняем с инвалидацией кеша
        self::save($cart, $userId);
        
        // Асинхронное логирование и аудит
        self::logCartAction('add', $productId, $quantity, $newQuantity, $userId, $cityId);
        
        return $cart;
    }
    
    /**
     * Обновить количество товара
     */
    public static function update(int $productId, int $quantity, ?int $userId = null): array
    {
        if ($quantity <= 0) {
            return self::remove($productId, $userId);
        }
        
        if ($quantity > self::MAX_QUANTITY) {
            throw new CartException('Превышено максимальное количество товара');
        }
        
        $cart = self::get($userId);
        
        if (!isset($cart[$productId])) {
            throw new CartException('Товар не найден в корзине');
        }
        
        // Получаем информацию о товаре
        $product = self::getProductInfoCached($productId);
        if (!$product) {
            throw new CartException('Товар не найден');
        }
        
        // Проверяем бизнес-правила
        self::validateBusinessRules($product, $quantity);
        
        // Проверяем наличие
        $cityId = self::getCurrentCityId();
        $stock = self::getProductStockCached($productId, $cityId);
        
        self::validateAvailability($product, $quantity, $stock);
        
        // Обновляем корзину
        $cart[$productId]['quantity'] = $quantity;
        $cart[$productId]['updated_at'] = date('Y-m-d H:i:s');
        
        // Сохраняем
        self::save($cart, $userId);
        
        // Логирование
        self::logCartAction('update', $productId, $quantity, $quantity, $userId, $cityId);
        
        return $cart;
    }
    
    /**
     * Удалить товар из корзины
     */
    public static function remove(int $productId, ?int $userId = null): array
    {
        $cart = self::get($userId);
        
        if (!isset($cart[$productId])) {
            return $cart; // Товар уже удален
        }
        
        $removedQuantity = $cart[$productId]['quantity'];
        unset($cart[$productId]);
        
        self::save($cart, $userId);
        
        // Логирование
        self::logCartAction('remove', $productId, $removedQuantity, 0, $userId, null);
        
        return $cart;
    }
    
    /**
     * Очистить корзину полностью
     */
    public static function clear(?int $userId = null): void
    {
        $cart = self::get($userId);
        $itemsCount = count($cart);
        
        if ($itemsCount === 0) {
            return; // Корзина уже пуста
        }
        
        self::save([], $userId);
        
        // Логирование
        Logger::info('Корзина очищена', [
            'user_id' => $userId,
            'items_count' => $itemsCount
        ]);
        
        AuditService::log($userId, 'clear_cart', 'cart', null, [
            'items_count' => $itemsCount
        ]);
    }
    
    /**
     * Получить корзину с полной информацией о товарах
     */
    public static function getWithProducts(?int $userId = null): array
    {
        $cart = self::get($userId);
        
        if (empty($cart)) {
            return [
                'cart' => [],
                'products' => [],
                'summary' => self::getEmptySummary(),
                'warnings' => [],
                'meta' => self::getCartMeta()
            ];
        }
        
        $productIds = array_keys($cart);
        $cityId = self::getCurrentCityId();
        
        // Получаем все данные одним запросом
        $productsData = self::getProductsDataBatch($productIds, $cityId, $userId);
        
        // Проверяем доступность и формируем предупреждения
        $warnings = self::validateCartAvailability($cart, $productsData);
        
        // Рассчитываем итоги
        $summary = self::calculateSummary($cart, $productsData);
        
        return [
            'cart' => $cart,
            'products' => $productsData,
            'summary' => $summary,
            'warnings' => $warnings,
            'meta' => self::getCartMeta($cart)
        ];
    }
    
    /**
     * Интеллектуальное слияние корзин при авторизации
     */
    public static function mergeGuestCartWithUser(int $userId): void
    {
        if ($userId <= 0) {
            return;
        }
        
        // Используем блокировку для предотвращения гонки
        $lockKey = self::MERGE_LOCK_KEY . $userId;
        if (!self::acquireLock($lockKey)) {
            Logger::warning('Cart merge already in progress', ['user_id' => $userId]);
            return;
        }
        
        try {
            // Проверяем сессию
            if (!Session::isActive()) {
                Logger::warning('Session not active for cart merge', ['user_id' => $userId]);
                return;
            }
            
            $guestCart = self::getGuestCart();
            if (empty($guestCart)) {
                return; // Нечего объединять
            }
            
            $userCart = self::loadFromDatabase($userId);
            $cityId = self::getCurrentCityId();
            $mergedCount = 0;
            
            // Интеллектуальное объединение
            foreach ($guestCart as $productId => $item) {
                try {
                    // Получаем актуальные данные о товаре
                    $product = self::getProductInfoCached($productId);
                    if (!$product) {
                        continue; // Товар больше не существует
                    }
                    
                    // Получаем остатки
                    $stock = self::getProductStockCached($productId, $cityId);
                    if ($stock <= 0) {
                        continue; // Товар закончился
                    }
                    
                    // Рассчитываем новое количество
                    $currentQty = $userCart[$productId]['quantity'] ?? 0;
                    $guestQty = $item['quantity'] ?? 0;
                    $newQty = min($currentQty + $guestQty, $stock, self::MAX_QUANTITY);
                    
                    // Проверяем минимальную партию
                    $minSale = (int)($product['min_sale'] ?: 1);
                    if ($newQty < $minSale) {
                        continue;
                    }
                    
                    // Корректируем до кратности
                    $newQty = floor($newQty / $minSale) * $minSale;
                    
                    if ($newQty > $currentQty) {
                        $userCart[$productId] = [
                            'product_id' => $productId,
                            'quantity' => $newQty,
                            'added_at' => $currentQty > 0 ? $userCart[$productId]['added_at'] : ($item['added_at'] ?? date('Y-m-d H:i:s')),
                            'updated_at' => date('Y-m-d H:i:s'),
                            'city_id' => $cityId
                        ];
                        $mergedCount++;
                    }
                    
                } catch (\Exception $e) {
                    Logger::warning('Failed to merge cart item', [
                        'product_id' => $productId,
                        'error' => $e->getMessage()
                    ]);
                }
            }
            
            if ($mergedCount > 0) {
                // Сохраняем объединенную корзину
                self::saveToDatabase($userId, $userCart);
                
                // Инвалидируем кеш
                self::invalidateCache($userId);
                
                Logger::info('Корзины успешно объединены', [
                    'user_id' => $userId,
                    'guest_items' => count($guestCart),
                    'merged_items' => $mergedCount,
                    'total_items' => count($userCart)
                ]);
            }
            
            // Очищаем гостевую корзину
            self::clearGuestCart();
            
        } finally {
            // Освобождаем блокировку
            self::releaseLock($lockKey);
        }
    }
    
    /**
     * Получить статистику корзины
     */
    public static function getStats(?int $userId = null): array
    {
        $cart = self::get($userId);
        
        return [
            'items_count' => count($cart),
            'total_quantity' => array_sum(array_column($cart, 'quantity')),
            'session_id' => session_id() ?: null,
            'user_id' => $userId,
            'city_id' => self::getCurrentCityId(),
            'last_updated' => max(array_column($cart, 'updated_at') ?: [date('Y-m-d H:i:s')])
        ];
    }
    
    // === Приватные методы для работы с БД ===
    
    /**
     * Загрузить корзину из БД
     */
    private static function loadFromDatabase(int $userId): array
    {
        try {
            $stmt = Database::query(
                "SELECT payload, updated_at FROM carts WHERE user_id = ? LIMIT 1",
                [$userId]
            );
            
            $row = $stmt->fetch();
            if (!$row || !$row['payload']) {
                return [];
            }
            
            $cart = json_decode($row['payload'], true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                Logger::error('Invalid cart JSON in database', [
                    'user_id' => $userId,
                    'error' => json_last_error_msg()
                ]);
                return [];
            }
            
            return self::validateCartStructure($cart);
            
        } catch (\Exception $e) {
            Logger::error('Database cart loading failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }
    
    /**
     * Сохранить корзину
     */
    private static function save(array $cart, ?int $userId = null): void
    {
        try {
            if ($userId > 0) {
                self::saveToDatabase($userId, $cart);
                self::invalidateCache($userId);
            } else {
                self::saveToSession($cart);
                self::invalidateGuestCache();
            }
        } catch (\Exception $e) {
            Logger::error('Cart save failed', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            throw new CartException('Не удалось сохранить корзину');
        }
    }
    
    /**
     * Сохранить в БД с оптимизацией
     */
    private static function saveToDatabase(int $userId, array $cart): void
    {
        $payload = json_encode($cart, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        
        Database::query(
            "INSERT INTO carts (user_id, payload, created_at, updated_at)
             VALUES (?, ?, NOW(), NOW())
             ON DUPLICATE KEY UPDATE 
             payload = VALUES(payload),
             updated_at = NOW()",
            [$userId, $payload]
        );
    }
    
    /**
     * Сохранить в сессию
     */
    private static function saveToSession(array $cart): void
    {
        Session::ensureStarted();
        Session::set(self::SESSION_KEY, $cart);
    }
    
    /**
     * Очистить гостевую корзину
     */
    private static function clearGuestCart(): void
    {
        Session::remove(self::SESSION_KEY);
        self::invalidateGuestCache();
    }
    
    // === Методы работы с товарами ===
    
    /**
     * Получить информацию о товаре с кешированием
     */
    private static function getProductInfoCached(int $productId): ?array
    {
        $cacheKey = 'product:info:' . $productId;
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return $cached;
        }
        
        $stmt = Database::query(
            "SELECT p.*, b.name as brand_name 
             FROM products p 
             LEFT JOIN brands b ON p.brand_id = b.brand_id
             WHERE p.product_id = ?",
            [$productId]
        );
        
        $product = $stmt->fetch() ?: null;
        
        if ($product) {
            Cache::set($cacheKey, $product, 3600); // 1 час
        }
        
        return $product;
    }
    
    /**
     * Получить остатки товара с кешированием
     */
    private static function getProductStockCached(int $productId, int $cityId): int
    {
        $cacheKey = "stock:{$productId}:{$cityId}";
        $cached = Cache::get($cacheKey);
        
        if ($cached !== null) {
            return (int)$cached;
        }
        
        $stmt = Database::query(
            "SELECT SUM(sb.quantity - sb.reserved) as available
             FROM stock_balances sb
             INNER JOIN city_warehouse_mapping cwm ON sb.warehouse_id = cwm.warehouse_id
             WHERE sb.product_id = ? AND cwm.city_id = ? AND sb.quantity > sb.reserved",
            [$productId, $cityId]
        );
        
        $stock = (int)($stmt->fetchColumn() ?: 0);
        
        Cache::set($cacheKey, $stock, 300); // 5 минут
        
        return $stock;
    }
    
    /**
     * Получить данные о товарах пакетно
     */
    private static function getProductsDataBatch(array $productIds, int $cityId, ?int $userId): array
    {
        if (empty($productIds)) {
            return [];
        }
        
        // Получаем статические данные
        $products = self::getProductsInfo($productIds);
        
        // Получаем динамические данные
        try {
            $dynamicService = new DynamicProductDataService();
            $dynamicData = $dynamicService->getProductsDynamicData($productIds, $cityId, $userId);
            
            // Объединяем данные
            foreach ($products as $productId => &$product) {
                if (isset($dynamicData[$productId])) {
                    $product['dynamic'] = $dynamicData[$productId];
                    $product['price'] = $dynamicData[$productId]['price']['final'] ?? null;
                    $product['base_price'] = $dynamicData[$productId]['price']['base'] ?? null;
                    $product['stock'] = $dynamicData[$productId]['stock']['quantity'] ?? 0;
                    $product['delivery'] = $dynamicData[$productId]['delivery'] ?? null;
                }
            }
        } catch (\Exception $e) {
            Logger::error('Failed to get dynamic product data', [
                'error' => $e->getMessage()
            ]);
        }
        
        return $products;
    }
    
    /**
     * Получить информацию о нескольких товарах
     */
    private static function getProductsInfo(array $productIds): array
    {
        $placeholders = implode(',', array_fill(0, count($productIds), '?'));
        
        $stmt = Database::query(
            "SELECT p.*, b.name as brand_name, s.name as series_name,
                    pi.url as image_url
             FROM products p
             LEFT JOIN brands b ON p.brand_id = b.brand_id
             LEFT JOIN series s ON p.series_id = s.series_id
             LEFT JOIN product_images pi ON pi.product_id = p.product_id AND pi.is_main = 1
             WHERE p.product_id IN ($placeholders)",
            $productIds
        );
        
        $products = [];
        while ($row = $stmt->fetch()) {
            $products[$row['product_id']] = $row;
        }
        
        return $products;
    }
    
    // === Валидация и бизнес-логика ===
    
    /**
     * Валидация запроса на добавление
     */
    private static function validateAddRequest(int $productId, int $quantity): void
    {
        if ($productId <= 0) {
            throw new CartException('Некорректный ID товара');
        }
        
        if ($quantity <= 0) {
            throw new CartException('Количество должно быть больше 0');
        }
        
        if ($quantity > self::MAX_QUANTITY) {
            throw new CartException('Превышено максимальное количество товара');
        }
    }
    
    /**
     * Валидация бизнес-правил
     */
    private static function validateBusinessRules(array $product, int $quantity): void
    {
        $minSale = (int)($product['min_sale'] ?: 1);
        
        if ($quantity < $minSale) {
            throw new CartException("Минимальная партия: {$minSale} {$product['unit']}");
        }
        
        if ($quantity % $minSale !== 0) {
            throw new CartException("Количество должно быть кратно {$minSale}");
        }
    }
    
    /**
     * Валидация лимитов корзины
     */
    private static function validateCartLimits(array $cart, int $productId): void
    {
        if (count($cart) >= self::MAX_ITEMS && !isset($cart[$productId])) {
            throw new CartException('Достигнут лимит товаров в корзине');
        }
    }
    
    /**
     * Валидация доступности товара
     */
    private static function validateAvailability(array $product, int $quantity, int $stock): void
    {
        if ($quantity > $stock) {
            throw new CartException(
                "Недостаточно товара на складе. Доступно: {$stock} {$product['unit']}"
            );
        }
    }
    
    /**
     * Валидация структуры корзины
     */
    private static function validateCartStructure($cart): array
    {
        if (!is_array($cart)) {
            return [];
        }
        
        $validated = [];
        
        foreach ($cart as $productId => $item) {
            if (!is_numeric($productId) || $productId <= 0) {
                continue;
            }
            
            if (!is_array($item) || !isset($item['quantity'])) {
                continue;
            }
            
            $validated[$productId] = [
                'product_id' => (int)$productId,
                'quantity' => (int)$item['quantity'],
                'added_at' => $item['added_at'] ?? date('Y-m-d H:i:s'),
                'updated_at' => $item['updated_at'] ?? date('Y-m-d H:i:s'),
                'city_id' => $item['city_id'] ?? self::getCurrentCityId()
            ];
        }
        
        return $validated;
    }
    
    /**
     * Проверка доступности товаров в корзине
     */
    private static function validateCartAvailability(array $cart, array $products): array
    {
        $warnings = [];
        
        foreach ($cart as $productId => $item) {
            if (!isset($products[$productId])) {
                $warnings[] = [
                    'type' => 'product_not_found',
                    'product_id' => $productId,
                    'message' => "Товар #{$productId} не найден"
                ];
                continue;
            }
            
            $product = $products[$productId];
            $stock = $product['stock'] ?? 0;
            $quantity = $item['quantity'];
            
            if ($stock <= 0) {
                $warnings[] = [
                    'type' => 'out_of_stock',
                    'product_id' => $productId,
                    'product_name' => $product['name'],
                    'message' => "Товар '{$product['name']}' отсутствует на складе"
                ];
            } elseif ($quantity > $stock) {
                $warnings[] = [
                    'type' => 'insufficient_stock',
                    'product_id' => $productId,
                    'product_name' => $product['name'],
                    'requested' => $quantity,
                    'available' => $stock,
                    'message' => "Товар '{$product['name']}': доступно только {$stock} {$product['unit']}"
                ];
            }
            
            // Проверяем минимальную партию
            $minSale = (int)($product['min_sale'] ?: 1);
            if ($quantity % $minSale !== 0) {
                $warnings[] = [
                    'type' => 'invalid_quantity',
                    'product_id' => $productId,
                    'product_name' => $product['name'],
                    'message' => "Количество должно быть кратно {$minSale}"
                ];
            }
        }
        
        return $warnings;
    }
    
    // === Вспомогательные методы ===
    
    /**
     * Получить текущий город
     */
    private static function getCurrentCityId(): int
    {
        // Приоритеты: cookie -> session -> default
        if (isset($_COOKIE['selected_city_id'])) {
            return (int)$_COOKIE['selected_city_id'];
        }
        
        $cityId = Session::get('city_id');
        if ($cityId) {
            return (int)$cityId;
        }
        
        return 1; // Москва по умолчанию
    }
    
    /**
     * Обновить элемент корзины
     */
    private static function updateCartItem(array $cart, int $productId, int $quantity, int $cityId): array
    {
        if (isset($cart[$productId])) {
            $cart[$productId]['quantity'] = $quantity;
            $cart[$productId]['updated_at'] = date('Y-m-d H:i:s');
        } else {
            $cart[$productId] = [
                'product_id' => $productId,
                'quantity' => $quantity,
                'added_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
                'city_id' => $cityId
            ];
        }
        
        return $cart;
    }
    
    /**
     * Рассчитать итоги корзины
     */
    private static function calculateSummary(array $cart, array $products): array
    {
        $summary = [
            'items_count' => 0,
            'total_quantity' => 0,
            'subtotal' => 0,
            'discount' => 0,
            'total' => 0,
            'savings_percent' => 0,
            'weight' => 0
        ];
        
        foreach ($cart as $productId => $item) {
            if (!isset($products[$productId])) {
                continue;
            }
            
            $product = $products[$productId];
            $quantity = $item['quantity'];
            $price = $product['price'] ?? 0;
            $basePrice = $product['base_price'] ?? $price;
            
            $summary['items_count']++;
            $summary['total_quantity'] += $quantity;
            
            $lineTotal = $price * $quantity;
            $lineBase = $basePrice * $quantity;
            
            $summary['subtotal'] += $lineBase;
            $summary['discount'] += ($lineBase - $lineTotal);
            
            // Добавляем вес если есть
            if (isset($product['weight'])) {
                $summary['weight'] += $product['weight'] * $quantity;
            }
        }
        
        $summary['total'] = $summary['subtotal'] - $summary['discount'];
        
        if ($summary['subtotal'] > 0) {
            $summary['savings_percent'] = round(($summary['discount'] / $summary['subtotal']) * 100, 1);
        }
        
        return $summary;
    }
    
    /**
     * Получить метаданные корзины
     */
    private static function getCartMeta(array $cart = []): array
    {
        return [
            'items_limit' => self::MAX_ITEMS,
            'quantity_limit' => self::MAX_QUANTITY,
            'can_add_more' => count($cart) < self::MAX_ITEMS,
            'session_id' => session_id() ?: null,
            'city_id' => self::getCurrentCityId()
        ];
    }
    
    /**
     * Получить пустые итоги
     */
    private static function getEmptySummary(): array
    {
        return [
            'items_count' => 0,
            'total_quantity' => 0,
            'subtotal' => 0,
            'discount' => 0,
            'total' => 0,
            'savings_percent' => 0,
            'weight' => 0
        ];
    }
    
    // === Работа с кешем ===
    
    /**
     * Инвалидировать кеш пользователя
     */
    private static function invalidateCache(int $userId): void
    {
        Cache::delete(self::CACHE_PREFIX . 'user:' . $userId);
    }
    
    /**
     * Инвалидировать кеш гостя
     */
    private static function invalidateGuestCache(): void
    {
        $sessionId = session_id();
        if ($sessionId) {
            Cache::delete(self::CACHE_PREFIX . 'guest:' . $sessionId);
        }
    }
    
    // === Блокировки для атомарности операций ===
    
    /**
     * Захватить блокировку
     */
    private static function acquireLock(string $key): bool
    {
        return Cache::set($key, 1, self::MERGE_LOCK_TTL);
    }
    
    /**
     * Освободить блокировку
     */
    private static function releaseLock(string $key): void
    {
        Cache::delete($key);
    }
    
    // === Логирование и аудит ===
    
    /**
     * Асинхронное логирование действий с корзиной
     */
    private static function logCartAction(
        string $action,
        int $productId,
        int $quantity,
        int $totalQuantity,
        ?int $userId,
        ?int $cityId
    ): void {
        // Добавляем в очередь для асинхронной обработки
        try {
            QueueService::push('audit', [
                'user_id' => $userId,
                'action' => $action . '_cart',
                'object_type' => 'cart',
                'object_id' => $productId,
                'details' => [
                    'quantity' => $quantity,
                    'total_quantity' => $totalQuantity,
                    'city_id' => $cityId,
                    'session_id' => session_id()
                ]
            ], QueueService::PRIORITY_LOW);
        } catch (\Exception $e) {
            // Fallback на синхронное логирование
            Logger::info("Cart action: {$action}", [
                'product_id' => $productId,
                'quantity' => $quantity,
                'total_quantity' => $totalQuantity,
                'user_id' => $userId,
                'city_id' => $cityId
            ]);
        }
    }
}