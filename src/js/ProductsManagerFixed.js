// 🚀 ИСПРАВЛЕННЫЙ ProductsManager v2.0
// Решает все проблемы с поиском на странице товаров

import { showToast, showLoadingIndicator, hideLoadingIndicator } from './utils.js';
import { renderProductsTable } from './renderProducts.js';
import { loadAvailability } from './availability.js';

export class ProductsManagerFixed {
    constructor() {
        // Предотвращаем множественную инициализацию
        if (window.__productsManagerInstance) {
            console.warn('ProductsManager already initialized');
            return window.__productsManagerInstance;
        }

        console.log('🚀 Initializing ProductsManagerFixed...');
        
        // Состояние
        this.products = [];
        this.currentPage = 1;
        this.itemsPerPage = 20;
        this.totalProducts = 0;
        this.sortColumn = 'relevance';
        this.sortDirection = 'asc';
        this.filters = {};
        this.isLoading = false;
        this.searchDebounceTimer = null;
        this.lastSearchQuery = '';
        
        // Элементы DOM
        this.elements = {
            searchInput: null,
            searchButton: null,
            clearFiltersBtn: null,
            toggleAdvancedBtn: null,
            advancedFilters: null,
            brandFilter: null,
            categoryFilter: null,
            stockFilter: null,
            sortFilter: null,
            activeFiltersSection: null,
            productTable: null
        };
        
        // Кеш для API запросов
        this.cache = new Map();
        this.cacheTimeout = 60000; // 1 минута
        
        window.__productsManagerInstance = this;
    }

    /**
     * Инициализация после загрузки DOM
     */
    async init() {
        console.log('📋 ProductsManagerFixed init started...');
        
        // Находим все элементы
        this.findElements();
        
        // Восстанавливаем состояние
        this.restoreState();
        
        // Привязываем обработчики
        this.bindEventHandlers();
        
        // Синхронизируем с глобальными переменными (для обратной совместимости)
        this.syncGlobalVariables();
        
        // Проверяем URL параметры
        this.checkUrlParams();
        
        // Загружаем начальные данные
        await this.loadInitialData();
        
        console.log('✅ ProductsManagerFixed initialized successfully');
    }

    /**
     * Поиск элементов DOM
     */
    findElements() {
        this.elements.searchInput = document.getElementById('searchInput');
        this.elements.searchButton = document.getElementById('searchButton');
        this.elements.clearFiltersBtn = document.getElementById('clearFiltersBtn');
        this.elements.toggleAdvancedBtn = document.getElementById('toggleAdvancedBtn');
        this.elements.advancedFilters = document.getElementById('advancedFilters');
        this.elements.brandFilter = document.getElementById('brandFilter');
        this.elements.categoryFilter = document.getElementById('categoryFilter');
        this.elements.stockFilter = document.getElementById('stockFilter');
        this.elements.sortFilter = document.getElementById('sortFilter');
        this.elements.activeFiltersSection = document.getElementById('activeFiltersSection');
        this.elements.productTable = document.querySelector('.product-table');
        
        // Элементы пагинации
        this.elements.prevBtns = document.querySelectorAll('.prev-btn');
        this.elements.nextBtns = document.querySelectorAll('.next-btn');
        this.elements.pageInputs = document.querySelectorAll('#pageInput, #pageInputBottom');
        this.elements.itemsPerPageSelects = document.querySelectorAll('#itemsPerPageSelect, #itemsPerPageSelectBottom');
        
        console.log('📍 Found elements:', Object.keys(this.elements).filter(k => this.elements[k]));
    }

    /**
     * Восстановление состояния из localStorage
     */
    restoreState() {
        const savedState = localStorage.getItem('productsManagerState');
        if (savedState) {
            try {
                const state = JSON.parse(savedState);
                this.currentPage = state.currentPage || 1;
                this.itemsPerPage = state.itemsPerPage || 20;
                this.sortColumn = state.sortColumn || 'relevance';
                this.sortDirection = state.sortDirection || 'asc'; 
                this.filters = state.filters || {};
                this.lastSearchQuery = state.lastSearchQuery || '';
                
                console.log('📦 Restored state:', state);
            } catch (e) {
                console.warn('Failed to restore state:', e);
            }
        }
    }

    /**
     * Сохранение состояния
     */
    saveState() {
        const state = {
            currentPage: this.currentPage,
            itemsPerPage: this.itemsPerPage,
            sortColumn: this.sortColumn,
            sortDirection: this.sortDirection,
            filters: this.filters,
            lastSearchQuery: this.lastSearchQuery
        };
        
        localStorage.setItem('productsManagerState', JSON.stringify(state));
    }

    /**
     * Привязка обработчиков событий
     */
    bindEventHandlers() {
        // Поиск
        if (this.elements.searchInput) {
            // Обработка ввода с debounce
            this.elements.searchInput.addEventListener('input', (e) => {
                clearTimeout(this.searchDebounceTimer);
                this.searchDebounceTimer = setTimeout(() => {
                    this.handleSearch(e.target.value);
                }, 300);
            });
            
            // Обработка Enter
            this.elements.searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    clearTimeout(this.searchDebounceTimer);
                    this.handleSearch(e.target.value);
                }
            });
            
            // Установка сохраненного значения
            if (this.lastSearchQuery) {
                this.elements.searchInput.value = this.lastSearchQuery;
            }
        }
        
        // Кнопка поиска
        if (this.elements.searchButton) {
            this.elements.searchButton.addEventListener('click', () => {
                const query = this.elements.searchInput?.value || '';
                this.handleSearch(query);
            });
        }
        
        // Очистка фильтров
        if (this.elements.clearFiltersBtn) {
            this.elements.clearFiltersBtn.addEventListener('click', () => {
                this.clearAllFilters();
            });
        }
        
        // Расширенный поиск
        if (this.elements.toggleAdvancedBtn) {
            this.elements.toggleAdvancedBtn.addEventListener('click', () => {
                this.toggleAdvancedFilters();
            });
        }
        
        // Фильтры
        ['brandFilter', 'categoryFilter', 'stockFilter'].forEach(filterName => {
            if (this.elements[filterName]) {
                this.elements[filterName].addEventListener('change', (e) => {
                    this.handleFilterChange(filterName, e.target.value);
                });
            }
        });
        
        // Сортировка
        if (this.elements.sortFilter) {
            this.elements.sortFilter.addEventListener('change', (e) => {
                this.handleSortChange(e.target.value);
            });
        }
        
        // Пагинация
        this.elements.prevBtns.forEach(btn => {
            btn.addEventListener('click', () => this.changePage(this.currentPage - 1));
        });
        
        this.elements.nextBtns.forEach(btn => {
            btn.addEventListener('click', () => this.changePage(this.currentPage + 1));
        });
        
        this.elements.pageInputs.forEach(input => {
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.changePage(parseInt(e.target.value) || 1);
                }
            });
        });
        
        this.elements.itemsPerPageSelects.forEach(select => {
            select.addEventListener('change', (e) => {
                this.changeItemsPerPage(parseInt(e.target.value));
            });
        });
        
        // Город
        const citySelect = document.getElementById('citySelect');
        if (citySelect) {
            citySelect.addEventListener('change', () => {
                this.cache.clear(); // Очищаем кеш при смене города
                this.fetchProducts();
            });
        }
    }

    /**
     * Проверка URL параметров
     */
    checkUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        
        // Проверяем параметр search (от глобального поиска)
        const searchParam = urlParams.get('search');
        if (searchParam) {
            console.log('📌 Found search param in URL:', searchParam);
            this.filters.search = searchParam;
            this.lastSearchQuery = searchParam;
            
            if (this.elements.searchInput) {
                this.elements.searchInput.value = searchParam;
            }
            
            // Убираем параметр из URL
            const newUrl = new URL(window.location);
            newUrl.searchParams.delete('search');
            window.history.replaceState({}, '', newUrl);
        }
    }

    /**
     * Обработка поиска
     */
    handleSearch(query) {
        query = query.trim();
        
        console.log('🔍 Search query:', query);
        
        if (query === this.lastSearchQuery) {
            return; // Не повторяем тот же запрос
        }
        
        this.lastSearchQuery = query;
        
        if (query) {
            this.filters.search = query;
        } else {
            delete this.filters.search;
        }
        
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Обработка изменения фильтра
     */
    handleFilterChange(filterName, value) {
        console.log(`🎯 Filter changed: ${filterName} = ${value}`);
        
        if (value) {
            this.filters[filterName] = value;
        } else {
            delete this.filters[filterName];
        }
        
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Обработка изменения сортировки
     */
    handleSortChange(sortValue) {
        console.log('🔄 Sort changed:', sortValue);
        
        this.sortColumn = sortValue;
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Загрузка начальных данных
     */
    async loadInitialData() {
        // Загружаем товары только если есть таблица
        if (this.elements.productTable) {
            await this.fetchProducts();
        }
    }

    /**
     * Основной метод загрузки товаров
     */
    async fetchProducts() {
        if (this.isLoading) {
            console.log('⏳ Already loading...');
            return;
        }
        
        this.isLoading = true;
        showLoadingIndicator();
        
        try {
            // Собираем параметры для API
            const params = {
                page: this.currentPage,
                limit: this.itemsPerPage,
                sort: this.sortColumn,
                city_id: document.getElementById('citySelect')?.value || '1'
            };
            
            // Добавляем поисковый запрос
            if (this.filters.search) {
                params.q = this.filters.search;
            }
            
            // Добавляем фильтры
            if (this.filters.brandFilter) {
                params.brand_name = this.filters.brandFilter;
            }
            if (this.filters.categoryFilter) {
                params.category_id = this.filters.categoryFilter;
            }
            
            console.log('📤 API params:', params);
            
            // Проверяем кеш
            const cacheKey = JSON.stringify(params);
            const cached = this.getFromCache(cacheKey);
            if (cached) {
                console.log('📦 Using cached results');
                this.handleSearchResult(cached);
                return;
            }
            
            // Делаем запрос к API
            const response = await this.makeApiRequest(params);
            
            // Сохраняем в кеш
            this.saveToCache(cacheKey, response);
            
            // Обрабатываем результат
            this.handleSearchResult(response);
            
        } catch (error) {
            console.error('❌ Fetch error:', error);
            showToast('Ошибка при загрузке товаров', true);
            this.renderEmptyState();
        } finally {
            this.isLoading = false;
            hideLoadingIndicator();
        }
    }

    /**
     * Выполнение API запроса
     */
    async makeApiRequest(params) {
        const url = new URL('/api/search', window.location.origin);
        
        // Добавляем параметры
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                url.searchParams.append(key, value);
            }
        });
        
        console.log('🌐 API URL:', url.toString());
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('📥 API Response:', data);
        
        return data;
    }

    /**
     * Обработка результатов поиска
     */
    handleSearchResult(response) {
        if (response.success && response.data) {
            const data = response.data;
            
            this.products = data.products || [];
            this.totalProducts = data.total || 0;
            
            console.log(`✅ Found ${this.products.length} products (total: ${this.totalProducts})`);
            
            // Синхронизируем глобальные переменные
            this.syncGlobalVariables();
            
            // Рендерим таблицу
            this.renderProducts();
            
            // Обновляем UI
            this.updateUI();
            
            // Загружаем динамические данные
            if (this.products.length > 0) {
                this.loadDynamicData();
            }
        } else {
            console.error('❌ Invalid response:', response);
            this.renderEmptyState();
        }
    }

    /**
     * Рендеринг товаров
     */
    renderProducts() {
        console.log('🎨 Rendering products...');
        
        // Используем существующую функцию рендеринга
        if (typeof renderProductsTable === 'function') {
            renderProductsTable();
        } else {
            console.error('renderProductsTable function not found');
        }
    }

    /**
     * Рендеринг пустого состояния
     */
    renderEmptyState() {
        const tbody = document.querySelector('.product-table tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="15" class="text-center p-4">Товары не найдены</td></tr>';
        }
    }

    /**
     * Загрузка динамических данных (цены, наличие)
     */
    async loadDynamicData() {
        const productIds = this.products.map(p => p.product_id).filter(id => id > 0);
        
        if (productIds.length === 0) {
            return;
        }
        
        console.log('💰 Loading dynamic data for', productIds.length, 'products');
        
        try {
            await loadAvailability(productIds);
        } catch (error) {
            console.error('Failed to load availability:', error);
        }
    }

    /**
     * Обновление UI элементов
     */
    updateUI() {
        // Обновляем пагинацию
        this.updatePagination();
        
        // Обновляем активные фильтры
        this.updateActiveFilters();
        
        // Обновляем счетчики
        this.updateCounters();
    }

    /**
     * Обновление пагинации
     */
    updatePagination() {
        const totalPages = Math.ceil(this.totalProducts / this.itemsPerPage);
        
        // Обновляем текст
        document.querySelectorAll('#currentPage, #currentPageBottom').forEach(el => {
            if (el) el.textContent = this.currentPage;
        });
        
        document.querySelectorAll('#totalPages, #totalPagesBottom').forEach(el => {
            if (el) el.textContent = totalPages;
        });
        
        // Обновляем поля ввода
        this.elements.pageInputs.forEach(input => {
            if (input) input.value = this.currentPage;
        });
        
        this.elements.itemsPerPageSelects.forEach(select => {
            if (select) select.value = this.itemsPerPage;
        });
        
        // Управляем кнопками
        this.elements.prevBtns.forEach(btn => {
            if (btn) btn.disabled = this.currentPage <= 1;
        });
        
        this.elements.nextBtns.forEach(btn => {
            if (btn) btn.disabled = this.currentPage >= totalPages;
        });
    }

    /**
     * Обновление активных фильтров
     */
    updateActiveFilters() {
        const activeFilters = [];
        
        if (this.filters.search) {
            activeFilters.push(`Поиск: "${this.filters.search}"`);
        }
        
        if (this.filters.brandFilter) {
            activeFilters.push(`Бренд: ${this.filters.brandFilter}`);
        }
        
        if (this.filters.categoryFilter) {
            activeFilters.push(`Категория: ${this.filters.categoryFilter}`);
        }
        
        if (this.elements.activeFiltersSection) {
            if (activeFilters.length > 0) {
                this.elements.activeFiltersSection.style.display = 'block';
                const filtersList = document.getElementById('activeFiltersList');
                if (filtersList) {
                    filtersList.textContent = activeFilters.join(', ');
                }
            } else {
                this.elements.activeFiltersSection.style.display = 'none';
            }
        }
    }

    /**
     * Обновление счетчиков
     */
    updateCounters() {
        document.querySelectorAll('#totalProductsText, #totalProductsTextBottom').forEach(el => {
            if (el) el.textContent = `Найдено товаров: ${this.totalProducts}`;
        });
    }

    /**
     * Изменение страницы
     */
    changePage(page) {
        const totalPages = Math.ceil(this.totalProducts / this.itemsPerPage);
        page = Math.max(1, Math.min(page, totalPages));
        
        if (page === this.currentPage) {
            return;
        }
        
        this.currentPage = page;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Изменение количества товаров на странице
     */
    changeItemsPerPage(itemsPerPage) {
        if (itemsPerPage === this.itemsPerPage) {
            return;
        }
        
        this.itemsPerPage = itemsPerPage;
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Очистка всех фильтров
     */
    clearAllFilters() {
        console.log('🧹 Clearing all filters');
        
        this.filters = {};
        this.lastSearchQuery = '';
        
        // Очищаем UI
        if (this.elements.searchInput) {
            this.elements.searchInput.value = '';
        }
        
        ['brandFilter', 'categoryFilter', 'stockFilter'].forEach(filterName => {
            if (this.elements[filterName]) {
                this.elements[filterName].value = '';
            }
        });
        
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Переключение расширенных фильтров
     */
    toggleAdvancedFilters() {
        if (this.elements.advancedFilters) {
            const isVisible = this.elements.advancedFilters.style.display !== 'none';
            this.elements.advancedFilters.style.display = isVisible ? 'none' : 'block';
            
            if (this.elements.toggleAdvancedBtn) {
                this.elements.toggleAdvancedBtn.innerHTML = isVisible ? 
                    '<i class="fas fa-sliders-h"></i> Расширенный поиск' : 
                    '<i class="fas fa-times"></i> Скрыть фильтры';
            }
        }
    }

    /**
     * Синхронизация с глобальными переменными
     */
    syncGlobalVariables() {
        window.productsData = this.products;
        window.currentPage = this.currentPage;
        window.itemsPerPage = this.itemsPerPage;
        window.totalProducts = this.totalProducts;
        window.sortColumn = this.sortColumn;
        window.sortDirection = this.sortDirection;
        window.appliedFilters = this.filters;
    }

    /**
     * Работа с кешем
     */
    getFromCache(key) {
        const cached = this.cache.get(key);
        if (cached && (Date.now() - cached.timestamp < this.cacheTimeout)) {
            return cached.data;
        }
        this.cache.delete(key);
        return null;
    }

    saveToCache(key, data) {
        this.cache.set(key, {
            data: data,
            timestamp: Date.now()
        });
        
        // Ограничиваем размер кеша
        if (this.cache.size > 50) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
    }

    /**
     * Обработка сортировки колонок таблицы
     */
    sortProducts(column) {
        console.log('🔄 Sort by column:', column);
        
        // Маппинг колонок на типы сортировки
        const sortMap = {
            'name': 'name',
            'external_id': 'external_id',
            'price': 'price_asc',
            'availability': 'availability',
            'orders_count': 'popularity'
        };
        
        const newSort = sortMap[column] || 'relevance';
        
        if (this.sortColumn === newSort && newSort.includes('price')) {
            // Переключаем направление для цены
            this.sortColumn = this.sortColumn === 'price_asc' ? 'price_desc' : 'price_asc';
        } else {
            this.sortColumn = newSort;
        }
        
        // Обновляем select если есть
        if (this.elements.sortFilter) {
            this.elements.sortFilter.value = this.sortColumn;
        }
        
        this.currentPage = 1;
        this.saveState();
        this.fetchProducts();
    }

    /**
     * Публичный метод для внешнего вызова
     */
    async loadPage(page) {
        this.changePage(page);
    }
}

// Создаем экземпляр
export const productsManager = new ProductsManagerFixed();