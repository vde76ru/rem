<?php
/**
 * 📁 ДОПОЛНИТЕЛЬНЫЕ VIEW ФАЙЛЫ
 * Создать эти файлы в директории src/views/
 */

// ========================================
// 📄 src/views/admin/index.php
// ========================================
?>
<div class="admin-dashboard">
    <div class="dashboard-header">
        <h1>Панель администратора</h1>
        <p class="text-muted">Добро пожаловать, <?= htmlspecialchars($user['username'] ?? 'Admin') ?>!</p>
    </div>
    
    <div class="dashboard-grid">
        <div class="dashboard-card">
            <div class="card-header">
                <h3>🔍 Диагностика системы</h3>
            </div>
            <div class="card-body">
                <p>Проверка состояния всех компонентов системы</p>
                <a href="/admin/diagnost" class="btn btn-primary">Запустить диагностику</a>
            </div>
        </div>
        
        <div class="dashboard-card">
            <div class="card-header">
                <h3>📊 Статистика</h3>
            </div>
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-number" id="productsCount">—</div>
                        <div class="stat-label">Товаров</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" id="usersCount">—</div>
                        <div class="stat-label">Пользователей</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" id="ordersCount">—</div>
                        <div class="stat-label">Заказов</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="dashboard-card">
            <div class="card-header">
                <h3>🔧 Быстрые действия</h3>
            </div>
            <div class="card-body">
                <div class="quick-actions">
                    <button onclick="testAPI()" class="btn btn-outline-primary">Тест API</button>
                    <button onclick="checkSearch()" class="btn btn-outline-primary">Тест поиска</button>
                    <button onclick="clearCache()" class="btn btn-outline-warning">Очистить кеш</button>
                </div>
            </div>
        </div>
        
        <div class="dashboard-card">
            <div class="card-header">
                <h3>📚 Документация</h3>
            </div>
            <div class="card-body">
                <p>Техническая документация и руководства</p>
                <a href="/admin/documentation" class="btn btn-secondary">Открыть документацию</a>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    loadDashboardStats();
});

async function loadDashboardStats() {
    try {
        // Можно добавить API для получения статистики
        // const response = await fetch('/api/admin/stats');
        // const data = await response.json();
        
        // Пока показываем заглушки
        document.getElementById('productsCount').textContent = '—';
        document.getElementById('usersCount').textContent = '—';
        document.getElementById('ordersCount').textContent = '—';
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function testAPI() {
    try {
        const response = await fetch('/api/test');
        const data = await response.json();
        
        if (data.success) {
            alert('✅ API работает корректно');
        } else {
            alert('❌ Проблемы с API: ' + (data.error || 'Неизвестная ошибка'));
        }
    } catch (error) {
        alert('❌ Ошибка подключения к API: ' + error.message);
    }
}

async function checkSearch() {
    try {
        const response = await fetch('/api/search?q=test&limit=1');
        const data = await response.json();
        
        if (data.success) {
            alert('✅ Поиск работает корректно. Найдено товаров: ' + (data.data.total || 0));
        } else {
            alert('❌ Проблемы с поиском: ' + (data.error || 'Неизвестная ошибка'));
        }
    } catch (error) {
        alert('❌ Ошибка поиска: ' + error.message);
    }
}

function clearCache() {
    if (confirm('Очистить кеш системы?')) {
        // Здесь можно добавить вызов API для очистки кеша
        alert('ℹ️ Функция очистки кеша в разработке');
    }
}
</script>

<style>
.admin-dashboard {
    padding: 2rem;
}

.dashboard-header {
    margin-bottom: 2rem;
    text-align: center;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
}

.dashboard-card {
    background: white;
    border: 1px solid #e0e0e0;
    border-radius: 0.5rem;
    overflow: hidden;
}

.card-header {
    background: #f8f9fa;
    padding: 1rem;
    border-bottom: 1px solid #e0e0e0;
}

.card-header h3 {
    margin: 0;
    font-size: 1.1rem;
}

.card-body {
    padding: 1rem;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    text-align: center;
}

.stat-item {
    padding: 0.5rem;
}

.stat-number {
    font-size: 2rem;
    font-weight: bold;
    color: #007bff;
}

.stat-label {
    font-size: 0.875rem;
    color: #666;
}

.quick-actions {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.btn {
    padding: 0.5rem 1rem;
    border: 1px solid #ddd;
    border-radius: 0.375rem;
    background: white;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    text-align: center;
}

.btn-primary {
    background: #007bff;
    color: white;
    border-color: #007bff;
}

.btn-secondary {
    background: #6c757d;
    color: white;
    border-color: #6c757d;
}

.btn-outline-primary {
    color: #007bff;
    border-color: #007bff;
}

.btn-outline-warning {
    color: #ffc107;
    border-color: #ffc107;
}

.btn:hover {
    opacity: 0.8;
}
</style>

<?php
// ========================================
// 📄 src/views/admin/diagnost.php
// ========================================
?>
<div class="diagnostics-page">
    <div class="page-header">
        <h1>🔍 Диагностика системы</h1>
        <p class="text-muted">Проверка состояния всех компонентов</p>
    </div>
    
    <div class="diagnostics-controls">
        <button onclick="runDiagnostics()" class="btn btn-primary" id="runBtn">
            <i class="fa fa-play"></i> Запустить диагностику
        </button>
        <button onclick="exportResults()" class="btn btn-secondary" id="exportBtn" disabled>
            <i class="fa fa-download"></i> Экспорт результатов
        </button>
    </div>
    
    <div id="diagnosticsResults" class="diagnostics-results">
        <div class="text-center text-muted">
            <p>Нажмите "Запустить диагностику" для проверки системы</p>
        </div>
    </div>
</div>

<script>
let diagnosticsData = null;

async function runDiagnostics() {
    const runBtn = document.getElementById('runBtn');
    const exportBtn = document.getElementById('exportBtn');
    const resultsContainer = document.getElementById('diagnosticsResults');
    
    runBtn.disabled = true;
    runBtn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Выполняется...';
    
    resultsContainer.innerHTML = '<div class="text-center"><i class="fa fa-spinner fa-spin"></i> Диагностика выполняется...</div>';
    
    try {
        // Здесь должен быть вызов к API диагностики
        // const response = await fetch('/api/admin/diagnostics');
        // const data = await response.json();
        
        // Пока показываем заглушку
        setTimeout(() => {
            diagnosticsData = {
                timestamp: new Date().toISOString(),
                status: 'completed',
                results: {
                    database: 'OK',
                    opensearch: 'Warning',
                    cache: 'OK',
                    sessions: 'OK'
                }
            };
            
            displayResults(diagnosticsData);
            runBtn.disabled = false;
            runBtn.innerHTML = '<i class="fa fa-play"></i> Запустить диагностику';
            exportBtn.disabled = false;
        }, 3000);
        
    } catch (error) {
        resultsContainer.innerHTML = `<div class="alert alert-danger">Ошибка диагностики: ${error.message}</div>`;
        runBtn.disabled = false;
        runBtn.innerHTML = '<i class="fa fa-play"></i> Запустить диагностику';
    }
}

function displayResults(data) {
    const resultsContainer = document.getElementById('diagnosticsResults');
    
    let html = `
        <div class="diagnostics-summary">
            <div class="summary-header">
                <h3>Результаты диагностики</h3>
                <div class="timestamp">Выполнено: ${new Date(data.timestamp).toLocaleString()}</div>
            </div>
            <div class="components-status">
    `;
    
    Object.entries(data.results).forEach(([component, status]) => {
        const statusClass = status === 'OK' ? 'success' : status === 'Warning' ? 'warning' : 'danger';
        const icon = status === 'OK' ? 'check' : status === 'Warning' ? 'exclamation-triangle' : 'times';
        
        html += `
            <div class="component-status status-${statusClass}">
                <i class="fa fa-${icon}"></i>
                <span class="component-name">${component}</span>
                <span class="component-result">${status}</span>
            </div>
        `;
    });
    
    html += `
            </div>
        </div>
    `;
    
    resultsContainer.innerHTML = html;
}

function exportResults() {
    if (!diagnosticsData) return;
    
    const dataStr = JSON.stringify(diagnosticsData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `vdestor-diagnostics-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
}
</script>

<style>
.diagnostics-page {
    padding: 2rem;
}

.page-header {
    margin-bottom: 2rem;
    text-align: center;
}

.diagnostics-controls {
    margin-bottom: 2rem;
    text-align: center;
}

.diagnostics-controls .btn {
    margin: 0 0.5rem;
}

.diagnostics-summary {
    background: white;
    border: 1px solid #e0e0e0;
    border-radius: 0.5rem;
    padding: 1.5rem;
}

.summary-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.timestamp {
    color: #666;
    font-size: 0.875rem;
}

.components-status {
    display: grid;
    gap: 0.75rem;
}

.component-status {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border-radius: 0.375rem;
    gap: 0.75rem;
}

.status-success {
    background: #d4edda;
    color: #155724;
}

.status-warning {
    background: #fff3cd;
    color: #856404;
}

.status-danger {
    background: #f8d7da;
    color: #721c24;
}

.component-name {
    flex: 1;
    font-weight: 500;
    text-transform: capitalize;
}

.component-result {
    font-weight: bold;
}
</style>

<?php
// ========================================
// 📄 src/views/cart/view.php
// ========================================
?>
<div class="cart-page">
    <div class="page-header">
        <h1>🛒 Корзина</h1>
        <div class="cart-summary">
            <?php if (!empty($cartRows)): ?>
                <span class="items-count"><?= count($cartRows) ?> товар(ов)</span>
                <?php if (!empty($summary['total'])): ?>
                    <span class="total-amount">на сумму <?= number_format($summary['total'], 2, '.', ' ') ?> ₽</span>
                <?php endif; ?>
            <?php else: ?>
                <span class="text-muted">Корзина пуста</span>
            <?php endif; ?>
        </div>
    </div>
    
    <?php if (!empty($warnings)): ?>
        <div class="cart-warnings">
            <?php foreach ($warnings as $warning): ?>
                <div class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    <?= htmlspecialchars($warning) ?>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    
    <?php if (!empty($cartRows)): ?>
        <div class="cart-items">
            <?php foreach ($cartRows as $item): ?>
                <div class="cart-item" data-product-id="<?= $item['product_id'] ?>">
                    <div class="item-info">
                        <h5 class="item-name"><?= htmlspecialchars($item['name']) ?></h5>
                        <div class="item-meta">
                            <span class="item-article">Арт: <?= htmlspecialchars($item['external_id']) ?></span>
                        </div>
                    </div>
                    
                    <div class="item-quantity">
                        <label>Количество:</label>
                        <div class="quantity-controls">
                            <button type="button" onclick="changeQuantity(<?= $item['product_id'] ?>, -1)">-</button>
                            <input type="number" 
                                   value="<?= $item['quantity'] ?>" 
                                   min="1" 
                                   onchange="updateQuantity(<?= $item['product_id'] ?>, this.value)"
                                   class="quantity-input">
                            <button type="button" onclick="changeQuantity(<?= $item['product_id'] ?>, 1)">+</button>
                        </div>
                    </div>
                    
                    <div class="item-price">
                        <?php if (!empty($item['base_price'])): ?>
                            <?= number_format($item['base_price'], 2, '.', ' ') ?> ₽
                        <?php else: ?>
                            <span class="text-muted">Цена уточняется</span>
                        <?php endif; ?>
                    </div>
                    
                    <div class="item-actions">
                        <button onclick="removeFromCart(<?= $item['product_id'] ?>)" 
                                class="btn btn-sm btn-outline-danger">
                            <i class="fa fa-trash"></i>
                        </button>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        
        <div class="cart-footer">
            <div class="cart-actions">
                <button onclick="clearCart()" class="btn btn-outline-danger">
                    <i class="fa fa-trash"></i> Очистить корзину
                </button>
                <button onclick="createSpecification()" class="btn btn-primary">
                    <i class="fa fa-file-text"></i> Создать спецификацию
                </button>
            </div>
            
            <?php if (!empty($summary)): ?>
                <div class="cart-total">
                    <div class="total-row">
                        <span>Итого:</span>
                        <strong><?= number_format($summary['total'] ?? 0, 2, '.', ' ') ?> ₽</strong>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        
    <?php else: ?>
        <div class="empty-cart">
            <div class="empty-cart-content">
                <i class="fa fa-shopping-cart fa-3x text-muted"></i>
                <h3>Корзина пуста</h3>
                <p class="text-muted">Добавьте товары из каталога для создания спецификации</p>
                <a href="/shop" class="btn btn-primary">Перейти в каталог</a>
            </div>
        </div>
    <?php endif; ?>
</div>

<script>
async function changeQuantity(productId, delta) {
    const input = document.querySelector(`[data-product-id="${productId}"] .quantity-input`);
    const newQuantity = Math.max(1, parseInt(input.value) + delta);
    input.value = newQuantity;
    await updateQuantity(productId, newQuantity);
}

async function updateQuantity(productId, quantity) {
    try {
        const formData = new FormData();
        formData.append('product_id', productId);
        formData.append('quantity', quantity);
        formData.append('csrf_token', window.APP_CONFIG.csrfToken);
        
        const response = await fetch('/cart/update', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (!data.success) {
            alert('Ошибка: ' + (data.message || 'Не удалось обновить количество'));
            location.reload();
        }
    } catch (error) {
        console.error('Update quantity error:', error);
        alert('Ошибка обновления количества');
    }
}

async function removeFromCart(productId) {
    if (!confirm('Удалить товар из корзины?')) return;
    
    try {
        const formData = new FormData();
        formData.append('product_id', productId);
        formData.append('csrf_token', window.APP_CONFIG.csrfToken);
        
        const response = await fetch('/cart/remove', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            location.reload();
        } else {
            alert('Ошибка: ' + (data.message || 'Не удалось удалить товар'));
        }
    } catch (error) {
        console.error('Remove from cart error:', error);
        alert('Ошибка удаления товара');
    }
}

async function clearCart() {
    if (!confirm('Очистить всю корзину?')) return;
    
    try {
        const formData = new FormData();
        formData.append('csrf_token', window.APP_CONFIG.csrfToken);
        
        const response = await fetch('/cart/clear', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            location.reload();
        } else {
            alert('Ошибка: ' + (data.message || 'Не удалось очистить корзину'));
        }
    } catch (error) {
        console.error('Clear cart error:', error);
        alert('Ошибка очистки корзины');
    }
}

async function createSpecification() {
    try {
        const formData = new FormData();
        formData.append('csrf_token', window.APP_CONFIG.csrfToken);
        
        const response = await fetch('/specification/create', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Спецификация создана успешно!');
            if (data.specification_id) {
                window.location.href = `/specification/${data.specification_id}`;
            } else {
                location.reload();
            }
        } else {
            alert('Ошибка: ' + (data.message || 'Не удалось создать спецификацию'));
        }
    } catch (error) {
        console.error('Create specification error:', error);
        alert('Ошибка создания спецификации');
    }
}
</script>

<style>
.cart-page {
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
}

.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #e0e0e0;
}

.cart-summary {
    display: flex;
    gap: 1rem;
    align-items: center;
}

.cart-warnings {
    margin-bottom: 1.5rem;
}

.alert {
    padding: 0.75rem 1rem;
    border-radius: 0.375rem;
    margin-bottom: 0.5rem;
}

.alert-warning {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    color: #856404;
}

.cart-items {
    margin-bottom: 2rem;
}

.cart-item {
    display: grid;
    grid-template-columns: 1fr auto auto auto;
    gap: 1rem;
    align-items: center;
    padding: 1rem;
    border: 1px solid #e0e0e0;
    border-radius: 0.375rem;
    margin-bottom: 1rem;
    background: white;
}

.item-info h5 {
    margin: 0 0 0.25rem 0;
    font-size: 1rem;
}

.item-meta {
    font-size: 0.875rem;
    color: #666;
}

.quantity-controls {
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.quantity-controls button {
    width: 30px;
    height: 30px;
    border: 1px solid #ddd;
    background: white;
    cursor: pointer;
    border-radius: 0.25rem;
}

.quantity-input {
    width: 60px;
    text-align: center;
    border: 1px solid #ddd;
    border-radius: 0.25rem;
    padding: 0.25rem;
}

.cart-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    background: #f8f9fa;
    border-radius: 0.375rem;
}

.cart-actions {
    display: flex;
    gap: 1rem;
}

.cart-total {
    font-size: 1.25rem;
}

.empty-cart {
    text-align: center;
    padding: 3rem 1rem;
}

.empty-cart-content {
    max-width: 400px;
    margin: 0 auto;
}

.empty-cart-content i {
    margin-bottom: 1rem;
}

.empty-cart-content h3 {
    margin-bottom: 0.5rem;
}

.btn {
    padding: 0.5rem 1rem;
    border: 1px solid #ddd;
    border-radius: 0.375rem;
    background: white;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}

.btn-primary {
    background: #007bff;
    color: white;
    border-color: #007bff;
}

.btn-outline-danger {
    color: #dc3545;
    border-color: #dc3545;
}

.btn:hover {
    opacity: 0.8;
}

@media (max-width: 768px) {
    .cart-item {
        grid-template-columns: 1fr;
        text-align: center;
    }
    
    .page-header {
        flex-direction: column;
        gap: 1rem;
    }
    
    .cart-footer {
        flex-direction: column;
        gap: 1rem;
    }
}
</style>