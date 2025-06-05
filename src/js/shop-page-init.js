// shop-page-init.js
// Скрипт инициализации для страницы товаров /shop

import { productsManager } from './ProductsManager.js';
import { showToast } from './utils.js';

// Глобальные переменные для совместимости со старым кодом
window.productsData = [];
window.currentPage = 1;
window.itemsPerPage = parseInt(sessionStorage.getItem('itemsPerPage')) || 20;
window.totalProducts = 0;
window.sortColumn = sessionStorage.getItem('sortColumn') || 'relevance';
window.sortDirection = sessionStorage.getItem('sortDirection') || 'asc';
window.appliedFilters = {};

// Инициализация при загрузке DOM
document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 Initializing shop page...');
    
    try {
        // Инициализируем менеджер товаров
        await productsManager.init();
        
        // Привязываем глобальные функции для обратной совместимости
        window.fetchProducts = () => productsManager.fetchProducts();
        window.sortProducts = (column) => productsManager.sortProducts(column);
        window.loadPage = (page) => productsManager.changePage(page);
        window.changeItemsPerPage = (value) => productsManager.changeItemsPerPage(value);
        
        console.log('✅ Shop page initialized successfully');
        
    } catch (error) {
        console.error('❌ Shop page initialization failed:', error);
        showToast('Ошибка инициализации страницы', true);
    }
});

// Экспорт для использования в других модулях
export { productsManager };