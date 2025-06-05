// 🚀 ИСПРАВЛЕННЫЙ main.js v2.0
// Правильная инициализация всех компонентов

import "../css/main.css";
import "../css/shop.css";

// ===== ПРОВЕРКА НА ПОВТОРНУЮ ИНИЦИАЛИЗАЦИЮ =====
if (window.__APP_INITIALIZED__) {
    console.warn('⚠️ App already initialized');
    throw new Error('App already initialized');
}
window.__APP_INITIALIZED__ = true;

// ===== ИМПОРТЫ МОДУЛЕЙ =====
import { showToast } from './utils.js';
import { productsManager } from './ProductsManagerFixed.js';
import { addToCart, clearCart, removeFromCart } from './cart.js';
import { createSpecification } from './specification.js';
import { cartBadge } from './cart-badge.js';

// ===== ГЛОБАЛЬНЫЙ ПОИСК В ХЕДЕРЕ =====
class GlobalSearchManager {
    constructor() {
        this.searchInput = null;
        this.searchSuggestions = null;
        this.debounceTimer = null;
    }

    init() {
        this.searchInput = document.getElementById('globalSearch');
        if (!this.searchInput) return;

        console.log('🔍 Initializing global search...');
        
        // Создаем контейнер для подсказок
        this.createSuggestionsDropdown();
        
        // Обработка ввода
        this.searchInput.addEventListener('input', (e) => {
            this.handleInput(e.target.value);
        });
        
        // Обработка Enter
        this.searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.performSearch(this.searchInput.value);
            }
        });
        
        // Закрытие подсказок при клике вне
        document.addEventListener('click', (e) => {
            if (!this.searchInput.contains(e.target) && 
                !this.searchSuggestions.contains(e.target)) {
                this.hideSuggestions();
            }
        });
    }

    createSuggestionsDropdown() {
        this.searchSuggestions = document.createElement('div');
        this.searchSuggestions.className = 'search-suggestions';
        this.searchSuggestions.style.cssText = `
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #e1e8ed;
            border-radius: 0 0 8px 8px;
            max-height: 400px;
            overflow-y: auto;
            display: none;
            z-index: 1000;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        `;
        
        const searchBox = this.searchInput.parentElement;
        searchBox.style.position = 'relative';
        searchBox.appendChild(this.searchSuggestions);
    }

    handleInput(value) {
        clearTimeout(this.debounceTimer);
        
        if (value.length < 2) {
            this.hideSuggestions();
            return;
        }
        
        this.debounceTimer = setTimeout(() => {
            this.fetchSuggestions(value);
        }, 300);
    }

    async fetchSuggestions(query) {
        try {
            const response = await fetch(`/api/autocomplete?q=${encodeURIComponent(query)}&limit=5`);
            const data = await response.json();
            
            if (data.success && data.suggestions) {
                this.showSuggestions(data.suggestions, query);
            }
        } catch (error) {
            console.error('Autocomplete error:', error);
        }
    }

    showSuggestions(suggestions, query) {
        this.searchSuggestions.innerHTML = '';
        
        if (suggestions.length === 0) {
            this.searchSuggestions.style.display = 'none';
            return;
        }
        
        suggestions.forEach(suggestion => {
            const item = document.createElement('div');
            item.className = 'suggestion-item';
            item.style.cssText = `
                padding: 12px 15px;
                cursor: pointer;
                transition: background 0.2s;
            `;
            
            item.innerHTML = this.highlightMatch(suggestion.text, query);
            
            item.addEventListener('mouseenter', () => {
                item.style.background = '#f5f5f5';
            });
            
            item.addEventListener('mouseleave', () => {
                item.style.background = '';
            });
            
            item.addEventListener('click', () => {
                this.searchInput.value = suggestion.text;
                this.performSearch(suggestion.text);
            });
            
            this.searchSuggestions.appendChild(item);
        });
        
        this.searchSuggestions.style.display = 'block';
    }

    highlightMatch(text, query) {
        const regex = new RegExp(`(${this.escapeRegex(query)})`, 'gi');
        return text.replace(regex, '<strong>$1</strong>');
    }

    escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    hideSuggestions() {
        this.searchSuggestions.style.display = 'none';
    }

    performSearch(query) {
        query = query.trim();
        if (!query) return;
        
        this.hideSuggestions();
        
        // Проверяем, на какой странице мы находимся
        const currentPath = window.location.pathname;
        
        if (currentPath === '/shop') {
            // Если мы уже на странице товаров, передаем запрос менеджеру
            if (productsManager && productsManager.handleSearch) {
                productsManager.handleSearch(query);
            }
        } else {
            // Иначе переходим на страницу товаров с параметром поиска
            window.location.href = `/shop?search=${encodeURIComponent(query)}`;
        }
    }
}

// ===== ГЛАВНЫЙ КЛАСС ПРИЛОЖЕНИЯ =====
class App {
    constructor() {
        this.modules = {
            globalSearch: new GlobalSearchManager(),
            productsManager: productsManager,
            cartBadge: cartBadge
        };
        
        this.initialized = false;
    }

    async init() {
        if (this.initialized) {
            console.warn('App already initialized');
            return;
        }
        
        console.log('🚀 Starting app initialization...');
        
        try {
            // Инициализация модулей
            this.modules.globalSearch.init();
            this.modules.cartBadge.init();
            
            // Инициализация менеджера товаров если мы на странице товаров
            if (document.querySelector('.product-table')) {
                await this.modules.productsManager.init();
            }
            
            // Общие обработчики
            this.bindGlobalHandlers();
            
            // Восстановление состояния
            this.restoreState();
            
            this.initialized = true;
            console.log('✅ App initialized successfully');
            
        } catch (error) {
            console.error('❌ App initialization failed:', error);
        }
    }

    bindGlobalHandlers() {
        // Город
        const citySelect = document.getElementById('citySelect');
        if (citySelect) {
            // Восстанавливаем выбранный город
            const savedCity = localStorage.getItem('selected_city_id');
            if (savedCity) {
                citySelect.value = savedCity;
            }
            
            citySelect.addEventListener('change', () => {
                const cityId = citySelect.value;
                const cityName = citySelect.options[citySelect.selectedIndex].text;
                
                localStorage.setItem('selected_city_id', cityId);
                document.cookie = `selected_city_id=${cityId};path=/;max-age=31536000`;
                
                showToast(`Город изменен на ${cityName}`);
            });
        }
        
        // Делегирование событий для динамического контента
        document.body.addEventListener('click', (e) => {
            const target = e.target;
            
            // Добавить в корзину
            if (target.closest('.add-to-cart-btn')) {
                e.preventDefault();
                const btn = target.closest('.add-to-cart-btn');
                const productId = btn.dataset.productId;
                const quantityInput = btn.closest('.cart-controls')?.querySelector('.quantity-input');
                const quantity = parseInt(quantityInput?.value || '1', 10);
                
                addToCart(productId, quantity);
            }
            
            // Удалить из корзины
            if (target.closest('.remove-from-cart-btn')) {
                e.preventDefault();
                const btn = target.closest('.remove-from-cart-btn');
                removeFromCart(btn.dataset.productId);
            }
            
            // Очистить корзину
            if (target.matches('#clearCartBtn')) {
                e.preventDefault();
                if (confirm('Очистить корзину?')) {
                    clearCart();
                }
            }
            
            // Создать спецификацию
            if (target.closest('.create-specification-btn, #createSpecLink')) {
                e.preventDefault();
                createSpecification();
            }
            
            // Сортировка таблицы
            const sortableHeader = target.closest('th.sortable');
            if (sortableHeader && sortableHeader.dataset.column) {
                e.preventDefault();
                if (productsManager && productsManager.sortProducts) {
                    productsManager.sortProducts(sortableHeader.dataset.column);
                }
            }
            
            // Фильтр по бренду/серии
            if (target.closest('.brand-name, .series-name')) {
                const element = target.closest('.brand-name, .series-name');
                const filterType = element.classList.contains('brand-name') ? 'brandFilter' : 'seriesFilter';
                const value = element.textContent.trim();
                
                if (productsManager && productsManager.handleFilterChange) {
                    productsManager.handleFilterChange(filterType, value);
                }
            }
        });
    }

    restoreState() {
        // Восстанавливаем состояние сайдбара
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            const sidebarCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
            if (sidebarCollapsed) {
                sidebar.classList.add('collapsed');
            }
        }
    }
}

// ===== ЭКСПОРТ ГЛОБАЛЬНЫХ ФУНКЦИЙ ДЛЯ ОБРАТНОЙ СОВМЕСТИМОСТИ =====
window.showToast = showToast;
window.addToCart = addToCart;
window.clearCart = clearCart;
window.removeFromCart = removeFromCart;
window.createSpecification = createSpecification;
window.updateCartBadge = () => cartBadge.update();

// Для совместимости со старым кодом
window.fetchProducts = () => {
    if (productsManager && productsManager.fetchProducts) {
        return productsManager.fetchProducts();
    }
};

window.sortProducts = (column) => {
    if (productsManager && productsManager.sortProducts) {
        return productsManager.sortProducts(column);
    }
};

window.loadPage = (page) => {
    if (productsManager && productsManager.loadPage) {
        return productsManager.loadPage(page);
    }
};

// ===== ЗАПУСК ПРИЛОЖЕНИЯ =====
const app = new App();

// Запускаем после загрузки DOM
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        app.init();
    });
} else {
    // DOM уже загружен
    app.init();
}