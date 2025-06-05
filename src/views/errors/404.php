<?php
/**
 * 📁 СТРУКТУРА VIEW ФАЙЛОВ ДЛЯ ОШИБОК
 * Создать эти файлы в директории src/views/
 */

// ========================================
// 📄 src/views/errors/404.php
// ========================================
?>
<div class="error-page">
    <div class="error-container">
        <div class="error-code">404</div>
        <div class="error-title">Страница не найдена</div>
        <div class="error-description">
            <p>К сожалению, запрашиваемая страница не существует.</p>
            <p>Возможно, она была удалена или вы ввели неверный адрес.</p>
        </div>
        <div class="error-actions">
            <a href="/" class="btn btn-primary">На главную</a>
            <a href="/shop" class="btn btn-secondary">В каталог</a>
        </div>
    </div>
</div>

<style>
.error-page {
    min-height: 60vh;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
}

.error-container {
    max-width: 500px;
    padding: 2rem;
}

.error-code {
    font-size: 6rem;
    font-weight: bold;
    color: #dc3545;
    line-height: 1;
    margin-bottom: 1rem;
}

.error-title {
    font-size: 2rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: #333;
}

.error-description {
    color: #666;
    margin-bottom: 2rem;
}

.error-actions {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
}

.btn {
    padding: 0.75rem 1.5rem;
    border-radius: 0.375rem;
    text-decoration: none;
    font-weight: 500;
    transition: all 0.2s;
}

.btn-primary {
    background-color: #007bff;
    color: white;
}

.btn-primary:hover {
    background-color: #0056b3;
}

.btn-secondary {
    background-color: #6c757d;
    color: white;
}

.btn-secondary:hover {
    background-color: #545b62;
}
</style>

<?php
// ========================================
// 📄 src/views/errors/500.php  
// ========================================
?>

<div class="error-page">
    <div class="error-container">
        <div class="error-code">500</div>
        <div class="error-title">Внутренняя ошибка сервера</div>
        <div class="error-description">
            <p>Произошла техническая ошибка на сервере.</p>
            <p>Мы уже работаем над её устранением.</p>
            <?php if (!empty($debug) && ($_ENV['APP_DEBUG'] ?? false)): ?>
                <details class="error-debug">
                    <summary>Техническая информация</summary>
                    <pre><?= htmlspecialchars(print_r($debug, true)) ?></pre>
                </details>
            <?php endif; ?>
        </div>
        <div class="error-actions">
            <a href="/" class="btn btn-primary">На главную</a>
            <button onclick="window.location.reload()" class="btn btn-secondary">Обновить страницу</button>
        </div>
    </div>
</div>

<?php
// ========================================
// 📄 src/views/home/index.php
// ========================================
?>

<div class="homepage">
    <div class="hero-section">
        <div class="container">
            <div class="hero-content">
                <h1>VDestor B2B</h1>
                <p class="lead">Электротехническое оборудование для профессионалов</p>
                <div class="hero-actions">
                    <a href="/shop" class="btn btn-primary btn-lg">Перейти в каталог</a>
                    <a href="/api/test" class="btn btn-outline-secondary">Проверить API</a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="features-section">
        <div class="container">
            <div class="row">
                <div class="col-md-4">
                    <div class="feature-card">
                        <h3>🔍 Умный поиск</h3>
                        <p>Найдите нужные товары по артикулу, названию или характеристикам</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card">
                        <h3>🚚 Доставка</h3>
                        <p>Быстрая доставка по всей России с учетом остатков на складах</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="feature-card">
                        <h3>📋 Спецификации</h3>
                        <p>Создавайте и сохраняйте спецификации для ваших проектов</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.homepage {
    min-height: 80vh;
}

.hero-section {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 4rem 0;
    text-align: center;
}

.hero-content h1 {
    font-size: 3.5rem;
    font-weight: bold;
    margin-bottom: 1rem;
}

.lead {
    font-size: 1.25rem;
    margin-bottom: 2rem;
}

.hero-actions {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
}

.features-section {
    padding: 4rem 0;
    background-color: #f8f9fa;
}

.feature-card {
    background: white;
    padding: 2rem;
    border-radius: 0.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    text-align: center;
    height: 100%;
}

.feature-card h3 {
    color: #333;
    margin-bottom: 1rem;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1rem;
}

.row {
    display: flex;
    flex-wrap: wrap;
    margin: -0.5rem;
}

.col-md-4 {
    flex: 0 0 33.333333%;
    padding: 0.5rem;
}

@media (max-width: 768px) {
    .col-md-4 {
        flex: 0 0 100%;
    }
    
    .hero-content h1 {
        font-size: 2.5rem;
    }
    
    .hero-actions {
        flex-direction: column;
        align-items: center;
    }
}
</style>

<?php
// ========================================
// 📄 src/views/shop/index.php
// ========================================
?>

<div class="shop-page">
    <div class="container">
        <div class="page-header">
            <h1>Каталог товаров</h1>
            <p class="text-muted">Найдите нужное электротехническое оборудование</p>
        </div>
        
        <div class="search-section">
            <div class="search-form">
                <input type="text" 
                       id="catalogSearch" 
                       class="form-control" 
                       placeholder="Поиск по артикулу, названию, бренду..."
                       value="<?= htmlspecialchars($_GET['q'] ?? '') ?>">
                <button type="button" class="btn btn-primary" onclick="performSearch()">
                    <i class="fa fa-search"></i> Найти
                </button>
            </div>
        </div>
        
        <div id="searchResults" class="search-results">
            <div class="text-center text-muted">
                <p>Введите запрос для поиска товаров</p>
                <p><small>Например: "автомат", "ABB", "выключатель 16А"</small></p>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('catalogSearch');
    const searchButton = document.querySelector('button[onclick="performSearch()"]');
    const resultsContainer = document.getElementById('searchResults');
    
    // Поиск по Enter
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
    
    // Если есть начальный запрос, выполняем поиск
    if (searchInput.value.trim()) {
        performSearch();
    }
});

async function performSearch() {
    const query = document.getElementById('catalogSearch').value.trim();
    const resultsContainer = document.getElementById('searchResults');
    
    if (!query) {
        resultsContainer.innerHTML = '<div class="text-center text-muted"><p>Введите запрос для поиска</p></div>';
        return;
    }
    
    // Показываем загрузку
    resultsContainer.innerHTML = '<div class="text-center"><i class="fa fa-spinner fa-spin"></i> Поиск...</div>';
    
    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=20`);
        const data = await response.json();
        
        if (data.success && data.data.products) {
            displaySearchResults(data.data);
        } else {
            resultsContainer.innerHTML = '<div class="alert alert-warning">Товары не найдены</div>';
        }
    } catch (error) {
        console.error('Search error:', error);
        resultsContainer.innerHTML = '<div class="alert alert-danger">Ошибка поиска. Попробуйте еще раз.</div>';
    }
}

function displaySearchResults(data) {
    const resultsContainer = document.getElementById('searchResults');
    const products = data.products || [];
    
    if (products.length === 0) {
        resultsContainer.innerHTML = '<div class="alert alert-info">По вашему запросу ничего не найдено</div>';
        return;
    }
    
    let html = `<div class="search-meta">Найдено товаров: ${data.total || products.length}</div>`;
    html += '<div class="products-grid">';
    
    products.forEach(product => {
        html += `
            <div class="product-card">
                <div class="product-info">
                    <h5 class="product-name">
                        <a href="/shop/product/${product.product_id}">${escapeHtml(product.name)}</a>
                    </h5>
                    <div class="product-meta">
                        <span class="product-article">Арт: ${escapeHtml(product.external_id)}</span>
                        ${product.brand_name ? `<span class="product-brand">${escapeHtml(product.brand_name)}</span>` : ''}
                    </div>
                </div>
                <div class="product-actions">
                    <a href="/shop/product/${product.product_id}" class="btn btn-sm btn-outline-primary">Подробнее</a>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    resultsContainer.innerHTML = html;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
</script>

<style>
.shop-page {
    padding: 2rem 0;
}

.page-header {
    text-align: center;
    margin-bottom: 2rem;
}

.search-section {
    margin-bottom: 2rem;
}

.search-form {
    display: flex;
    max-width: 600px;
    margin: 0 auto;
    gap: 0.5rem;
}

.search-form input {
    flex: 1;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 0.375rem;
}

.search-meta {
    margin-bottom: 1rem;
    color: #666;
    font-weight: 500;
}

.products-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
}

.product-card {
    background: white;
    border: 1px solid #e0e0e0;
    border-radius: 0.5rem;
    padding: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.product-name {
    margin: 0 0 0.5rem 0;
    font-size: 1rem;
}

.product-name a {
    color: #333;
    text-decoration: none;
}

.product-name a:hover {
    color: #007bff;
}

.product-meta {
    display: flex;
    gap: 1rem;
    font-size: 0.875rem;
    color: #666;
}

.product-actions {
    flex-shrink: 0;
}
</style>