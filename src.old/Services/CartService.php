<?php
namespace App\Services;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Session;
use App\Exceptions\CartException;

/**
 * Исправленный сервис для работы с корзиной
 * Устраняет проблемы с дублированием сессий и некорректными проверками
 */
class CartService
{
    const SESSION_KEY = 'cart';
    const MAX_ITEMS = 100;
    const MAX_QUANTITY = 9999;
    
    /**
     * Получить корзину - единая логика для всех случаев
     */
    public static function get(?int $userId = null): array
    {
        try {
            if ($userId > 0) {
                // Для авторизованных пользователей - только БД
                return self::loadFromDatabase($userId);
            } else {
                // Для гостей - только сессия
                return self::loadFromSession();
            }
        } catch (\Exception $e) {
            Logger::error('Cart loading error', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }
    
    /**
     * Добавить товар в корзину с проверкой наличия
     */
    public static function add(int $productId, int $quantity = 1, ?int $userId = null): array
    {
        if ($productId <= 0 || $quantity <= 0) {
            throw new CartException('Некорректные данные товара');
        }
        
        if ($quantity > self::MAX_QUANTITY) {
            throw new CartException('Превышено максимальное количество товара');
        }
        
        // Проверяем существование товара
        $product = self::getProductInfo($productId);
        if (!$product) {
            throw new CartException('Товар не найден');
        }
        
        // Проверяем минимальную партию
        $minSale = (int)($product['min_sale'] ?: 1);
        if ($quantity < $minSale) {
            throw new CartException("Минимальная партия: {$minSale} {$product['unit']}");
        }
        
        // Проверяем кратность минимальной партии
        if ($quantity % $minSale !== 0) {
            throw new CartException("Количество должно быть кратно {$minSale}");
        }
        
        // Получаем город из сессии/куки
        $cityId = self::getCurrentCityId();
        
        // Проверяем наличие товара
        $stock = self::getProductStock($productId, $cityId);
        if ($stock <= 0) {
            throw new CartException('Товар отсутствует на складе');
        }
        
        $cart = self::get($userId);
        
        // Проверяем лимит товаров в корзине
        if (count($cart) >= self::MAX_ITEMS && !isset($cart[$productId])) {
            throw new CartException('Достигнут лимит товаров в корзине');
        }
        
        // Проверяем общее количество с учетом уже добавленного
        $currentQuantity = $cart[$productId]['quantity'] ?? 0;
        $newQuantity = $currentQuantity + $quantity;
        
        if ($newQuantity > self::MAX_QUANTITY) {
            throw new CartException('Превышено максимальное количество товара');
        }
        
        if ($newQuantity > $stock) {
            throw new CartException("Недостаточно товара на складе. Доступно: {$stock} {$product['unit']}");
        }
        
        // Добавляем или обновляем товар в корзине
        if (isset($cart[$productId])) {
            $cart[$productId]['quantity'] = $newQuantity;
            $cart[$productId]['updated_at'] = date('Y-m-d H:i:s');
        } else {
            $cart[$productId] = [
                'product_id' => $productId,
                'quantity' => $quantity,
                'added_at' => date('Y-m-d H:i:s'),
                'city_id' => $cityId
            ];
        }
        
        self::save($cart, $userId);
        
        // Логируем добавление
        Logger::info('Товар добавлен в корзину', [
            'product_id' => $productId,
            'quantity' => $quantity,
            'total_quantity' => $newQuantity,
            'user_id' => $userId,
            'city_id' => $cityId
        ]);
        
        // Записываем в аудит
        AuditService::log($userId, 'add_to_cart', 'cart', $productId, [
            'quantity' => $quantity,
            'total_quantity' => $newQuantity
        ]);
        
        return $cart;
    }
    
    /**
     * Обновить количество товара с проверкой наличия
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
        
        // Проверяем товар
        $product = self::getProductInfo($productId);
        if (!$product) {
            throw new CartException('Товар не найден');
        }
        
        // Проверяем минимальную партию
        $minSale = (int)($product['min_sale'] ?: 1);
        if ($quantity < $minSale) {
            throw new CartException("Минимальная партия: {$minSale} {$product['unit']}");
        }
        
        if ($quantity % $minSale !== 0) {
            throw new CartException("Количество должно быть кратно {$minSale}");
        }
        
        // Проверяем наличие
        $cityId = self::getCurrentCityId();
        $stock = self::getProductStock($productId, $cityId);
        
        if ($quantity > $stock) {
            throw new CartException("Недостаточно товара. Доступно: {$stock} {$product['unit']}");
        }
        
        $cart[$productId]['quantity'] = $quantity;
        $cart[$productId]['updated_at'] = date('Y-m-d H:i:s');
        
        self::save($cart, $userId);
        
        return $cart;
    }
    
    /**
     * Удалить товар из корзины
     */
    public static function remove(int $productId, ?int $userId = null): array
    {
        $cart = self::get($userId);
        
        if (isset($cart[$productId])) {
            $removedQuantity = $cart[$productId]['quantity'];
            unset($cart[$productId]);
            self::save($cart, $userId);
            
            Logger::info('Товар удален из корзины', [
                'product_id' => $productId,
                'quantity' => $removedQuantity,
                'user_id' => $userId
            ]);
            
            AuditService::log($userId, 'remove_from_cart', 'cart', $productId, [
                'quantity' => $removedQuantity
            ]);
        }
        
        return $cart;
    }
    
    /**
     * Очистить корзину
     */
    public static function clear(?int $userId = null): void
    {
        $cart = self::get($userId);
        $itemsCount = count($cart);
        
        self::save([], $userId);
        
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
            return ['cart' => [], 'products' => [], 'summary' => self::getEmptySummary()];
        }
        
        $productIds = array_keys($cart);
        $cityId = self::getCurrentCityId();
        
        // Получаем статические данные товаров
        $products = self::getProductsInfo($productIds);
        
        // Получаем динамические данные (цены, остатки)
        $dynamicService = new DynamicProductDataService();
        $dynamicData = $dynamicService->getProductsDynamicData($productIds, $cityId, $userId);
        
        // Объединяем данные
        foreach ($products as $productId => &$product) {
            if (isset($dynamicData[$productId])) {
                $product['dynamic'] = $dynamicData[$productId];
                $product['price'] = $dynamicData[$productId]['price']['final'] ?? null;
                $product['stock'] = $dynamicData[$productId]['stock']['quantity'] ?? 0;
                $product['delivery'] = $dynamicData[$productId]['delivery'] ?? null;
            }
        }
        
        // Проверяем доступность товаров
        $warnings = [];
        foreach ($cart as $productId => $item) {
            if (!isset($products[$productId])) {
                $warnings[] = "Товар #{$productId} не найден";
                continue;
            }
            
            $product = $products[$productId];
            $stock = $product['stock'] ?? 0;
            
            if ($stock <= 0) {
                $warnings[] = "Товар '{$product['name']}' отсутствует на складе";
            } elseif ($item['quantity'] > $stock) {
                $warnings[] = "Товар '{$product['name']}': доступно только {$stock} {$product['unit']}";
            }
        }
        
        // Рассчитываем итоги
        $summary = self::calculateSummary($cart, $products);
        
        return [
            'cart' => $cart,
            'products' => $products,
            'summary' => $summary,
            'warnings' => $warnings
        ];
    }
    
    /**
     * Слияние гостевой корзины с пользовательской
     */
    public static function mergeGuestCartWithUser(int $userId): void
    {
        if ($userId <= 0) return;
        
        // Используем новый Session API
        if (!Session::isActive()) {
            error_log("WARNING: Session not active in mergeGuestCartWithUser");
            return;
        }
        
        $guestCart = self::loadFromSession();
        if (empty($guestCart)) return;
        
        $userCart = self::loadFromDatabase($userId);
        $cityId = self::getCurrentCityId();
        
        // Объединяем корзины с проверкой наличия
        foreach ($guestCart as $productId => $item) {
            try {
                $stock = self::getProductStock($productId, $cityId);
                $currentQty = $userCart[$productId]['quantity'] ?? 0;
                $newQty = min($currentQty + $item['quantity'], $stock, self::MAX_QUANTITY);
                
                if ($newQty > $currentQty) {
                    $userCart[$productId] = [
                        'product_id' => $productId,
                        'quantity' => $newQty,
                        'added_at' => $item['added_at'] ?? date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ];
                }
            } catch (\Exception $e) {
                Logger::warning('Failed to merge cart item', [
                    'product_id' => $productId,
                    'error' => $e->getMessage()
                ]);
            }
        }
        
        // Сохраняем объединенную корзину
        self::saveToDatabase($userId, $userCart);
        
        // Очищаем гостевую корзину
        self::clearSession();
        
        Logger::info('Корзины объединены', [
            'user_id' => $userId,
            'guest_items' => count($guestCart),
            'merged_items' => count($userCart)
        ]);
    }
    
    // === Приватные методы ===
    
    /**
     * Загрузить корзину из БД
     */
    private static function loadFromDatabase(int $userId): array
    {
        try {
            $stmt = Database::query(
                "SELECT payload FROM carts WHERE user_id = ? LIMIT 1",
                [$userId]
            );
            
            $row = $stmt->fetch();
            if ($row && $row['payload']) {
                $cart = json_decode($row['payload'], true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    return $cart;
                }
            }
        } catch (\Exception $e) {
            Logger::error('Ошибка загрузки корзины из БД', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
        }
        
        return [];
    }
    
    /**
     * Загрузить корзину из сессии - используем новый Session API
     */
    private static function loadFromSession(): array
    {
        try {
            return Session::get(self::SESSION_KEY, []);
        } catch (\Exception $e) {
            Logger::error('Ошибка загрузки корзины из сессии', [
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
        if ($userId > 0) {
            // Для авторизованных - только в БД
            self::saveToDatabase($userId, $cart);
        } else {
            // Для гостей - только в сессию
            self::saveToSession($cart);
        }
    }
    
    /**
     * Сохранить в БД
     */
    private static function saveToDatabase(int $userId, array $cart): void
    {
        try {
            $payload = json_encode($cart, JSON_UNESCAPED_UNICODE);
            
            Database::query(
                "INSERT INTO carts (user_id, payload, created_at, updated_at)
                 VALUES (?, ?, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE 
                 payload = VALUES(payload),
                 updated_at = NOW()",
                [$userId, $payload]
            );
        } catch (\Exception $e) {
            Logger::error('Ошибка сохранения корзины в БД', [
                'user_id' => $userId,
                'error' => $e->getMessage()
            ]);
            throw new CartException('Не удалось сохранить корзину');
        }
    }
    
    /**
     * Сохранить в сессию - используем новый Session API
     */
    private static function saveToSession(array $cart): void
    {
        try {
            Session::set(self::SESSION_KEY, $cart);
        } catch (\Exception $e) {
            Logger::error('Ошибка сохранения корзины в сессию', [
                'error' => $e->getMessage()
            ]);
            throw new CartException('Не удалось сохранить корзину');
        }
    }
    
    /**
     * Очистить сессию - используем новый Session API
     */
    private static function clearSession(): void
    {
        try {
            Session::remove(self::SESSION_KEY);
        } catch (\Exception $e) {
            Logger::error('Ошибка очистки корзины в сессии', [
                'error' => $e->getMessage()
            ]);
        }
    }
    
    /**
     * Получить информацию о товаре
     */
    private static function getProductInfo(int $productId): ?array
    {
        $stmt = Database::query(
            "SELECT p.*, b.name as brand_name 
             FROM products p 
             LEFT JOIN brands b ON p.brand_id = b.brand_id
             WHERE p.product_id = ?",
            [$productId]
        );
        return $stmt->fetch() ?: null;
    }
    
    /**
     * Получить информацию о нескольких товарах
     */
    private static function getProductsInfo(array $productIds): array
    {
        if (empty($productIds)) return [];
        
        $placeholders = implode(',', array_fill(0, count($productIds), '?'));
        $stmt = Database::query(
            "SELECT p.*, b.name as brand_name, s.name as series_name
             FROM products p
             LEFT JOIN brands b ON p.brand_id = b.brand_id
             LEFT JOIN series s ON p.series_id = s.series_id
             WHERE p.product_id IN ($placeholders)",
            $productIds
        );
        
        $products = [];
        while ($row = $stmt->fetch()) {
            $products[$row['product_id']] = $row;
        }
        
        return $products;
    }
    
    /**
     * Получить остатки товара для города
     */
    private static function getProductStock(int $productId, int $cityId): int
    {
        $stmt = Database::query(
            "SELECT SUM(sb.quantity - sb.reserved) as available
             FROM stock_balances sb
             INNER JOIN city_warehouse_mapping cwm ON sb.warehouse_id = cwm.warehouse_id
             WHERE sb.product_id = ? AND cwm.city_id = ? AND sb.quantity > sb.reserved",
            [$productId, $cityId]
        );
        
        return (int)($stmt->fetchColumn() ?: 0);
    }
    
    /**
     * Получить текущий город из сессии/cookie
     */
    private static function getCurrentCityId(): int
    {
        // Приоритет: cookie -> session -> default
        if (isset($_COOKIE['selected_city_id'])) {
            return (int)$_COOKIE['selected_city_id'];
        }
        
        if (Session::isActive()) {
            $cityId = Session::get('city_id');
            if ($cityId) {
                return (int)$cityId;
            }
        }
        
        return 1; // Москва по умолчанию
    }
    
    /**
     * Рассчитать итоги корзины
     */
    private static function calculateSummary(array $cart, array $products): array
    {
        $itemsCount = 0;
        $totalQuantity = 0;
        $subtotal = 0;
        $discount = 0;
        
        foreach ($cart as $productId => $item) {
            if (!isset($products[$productId])) continue;
            
            $product = $products[$productId];
            $quantity = $item['quantity'];
            $price = $product['price'] ?? 0;
            
            $itemsCount++;
            $totalQuantity += $quantity;
            $lineTotal = $price * $quantity;
            $subtotal += $lineTotal;
            
            // Рассчитываем скидку если есть спецпредложение
            if (isset($product['dynamic']['price'])) {
                $priceData = $product['dynamic']['price'];
                if ($priceData['has_special'] && $priceData['base']) {
                    $discount += ($priceData['base'] - $priceData['final']) * $quantity;
                }
            }
        }
        
        return [
            'items_count' => $itemsCount,
            'total_quantity' => $totalQuantity,
            'subtotal' => $subtotal,
            'discount' => $discount,
            'total' => $subtotal - $discount
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
            'total' => 0
        ];
    }
}