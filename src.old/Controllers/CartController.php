<?php
namespace App\Controllers;

use App\Services\CartService;
use App\Services\AuthService;
use App\Core\CSRF;
use App\Core\Layout;

class CartController extends BaseController
{
    /**
     * POST /cart/add — добавить товар в корзину
     */
    public function addAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            $productId = (int)($_POST['productId'] ?? $_POST['product_id'] ?? 0);
            $quantity  = (int)($_POST['quantity']  ?? 1);

            if ($productId <= 0 || $quantity <= 0) {
                $this->error('Некорректные данные товара', 400);
                return;
            }

            $userId = AuthService::check() ? AuthService::user()['id'] : null;

            CartService::add($productId, $quantity, $userId);
            
            // ✅ Унифицированный успешный ответ
            $this->success([
                'product_id' => $productId,
                'quantity' => $quantity,
                'cart_total' => count(CartService::get($userId))
            ], 'Товар добавлен в корзину');
            
        } catch (\Exception $e) {
            // ✅ Унифицированный ответ об ошибке
            $this->error($e->getMessage(), 400);
        }
    }

    /**
     * GET /cart — страница корзины
     */
    public function viewAction(): void
    {
        $userId = AuthService::check() ? AuthService::user()['id'] : null;
        $data = CartService::getWithProducts($userId);
        
        $rows = [];
        foreach ($data['cart'] as $pid => $item) {
            $product = $data['products'][$pid] ?? null;
            if (!$product) continue;
            
            $rows[] = [
                'product_id' => $pid,
                'name' => $product['name'],
                'external_id' => $product['external_id'],
                'quantity' => $item['quantity'],
                'base_price' => $product['base_price'] ?? 0,
            ];
        }
    
        Layout::render('cart/view', [
            'cartRows' => $rows,
            'cart' => $data['cart'],
            'products' => $data['products'],
            'summary' => $data['summary'] ?? [],
            'warnings' => $data['warnings'] ?? []
        ]);
    }

    /**
     * POST /cart/remove — удалить товар из корзины
     */
    public function removeAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                $this->error('Метод не разрешен', 405);
                return;
            }
            
            if (!CSRF::validate($_POST['csrf_token'] ?? '')) {
                $this->error('Недействительный CSRF токен', 403);
                return;
            }

            $productId = (int)($_POST['productId'] ?? $_POST['product_id'] ?? 0);
            if ($productId <= 0) {
                $this->error('Некорректный ID товара', 400);
                return;
            }

            $userId = AuthService::check() ? AuthService::user()['id'] : null;
            CartService::remove($productId, $userId);

            // ✅ Унифицированный успешный ответ
            $this->success([
                'product_id' => $productId,
                'cart_total' => count(CartService::get($userId))
            ], 'Товар удален из корзины');
            
        } catch (\Exception $e) {
            $this->error($e->getMessage(), 400);
        }
    }

    /**
     * POST /cart/update — обновить количество товара
     */
    public function updateAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                $this->error('Метод не разрешен', 405);
                return;
            }
            
            if (!CSRF::validate($_POST['csrf_token'] ?? '')) {
                $this->error('Недействительный CSRF токен', 403);
                return;
            }

            $productId = (int)($_POST['product_id'] ?? 0);
            $quantity = (int)($_POST['quantity'] ?? 0);
            
            if ($productId <= 0) {
                $this->error('Некорректный ID товара', 400);
                return;
            }

            $userId = AuthService::check() ? AuthService::user()['id'] : null;
            
            if ($quantity <= 0) {
                CartService::remove($productId, $userId);
                $message = 'Товар удален из корзины';
            } else {
                CartService::update($productId, $quantity, $userId);
                $message = 'Количество товара обновлено';
            }

            // ✅ Унифицированный успешный ответ
            $this->success([
                'product_id' => $productId,
                'quantity' => $quantity,
                'cart_total' => count(CartService::get($userId))
            ], $message);
            
        } catch (\Exception $e) {
            $this->error($e->getMessage(), 400);
        }
    }

    /**
     * POST /cart/clear — очистить корзину
     */
    public function clearAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                $this->error('Метод не разрешен', 405);
                return;
            }
            
            if (!CSRF::validate($_POST['csrf_token'] ?? '')) {
                $this->error('Недействительный CSRF токен', 403);
                return;
            }

            $userId = AuthService::check() ? AuthService::user()['id'] : null;
            $cartBefore = CartService::get($userId);
            $itemsCount = count($cartBefore);
            
            CartService::clear($userId);

            // ✅ Унифицированный успешный ответ
            $this->success([
                'items_cleared' => $itemsCount,
                'cart_total' => 0
            ], 'Корзина очищена');
            
        } catch (\Exception $e) {
            $this->error($e->getMessage(), 400);
        }
    }

    /**
     * GET /cart/json — получить корзину в JSON формате
     */
    public function getJsonAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            $userId = AuthService::check() ? AuthService::user()['id'] : null;
            $data = CartService::getWithProducts($userId);
            
            // ✅ Унифицированный успешный ответ
            $this->success([
                'cart' => $data['cart'],
                'products' => $data['products'],
                'summary' => $data['summary'],
                'warnings' => $data['warnings'] ?? []
            ], 'Данные корзины получены');
            
        } catch (\Exception $e) {
            $this->error($e->getMessage(), 500);
        }
    }

    /**
     * GET /cart/count — получить количество товаров в корзине (для счетчика)
     */
    public function getCountAction(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        
        try {
            $userId = AuthService::check() ? AuthService::user()['id'] : null;
            $cart = CartService::get($userId);
            
            $totalItems = 0;
            $totalQuantity = 0;
            
            foreach ($cart as $item) {
                $totalItems++;
                $totalQuantity += $item['quantity'] ?? 0;
            }
            
            // ✅ Унифицированный ответ для счетчика
            $this->success([
                'items_count' => $totalItems,
                'total_quantity' => $totalQuantity
            ]);
            
        } catch (\Exception $e) {
            $this->error($e->getMessage(), 500);
        }
    }
}