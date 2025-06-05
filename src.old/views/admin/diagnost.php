<?php
use App\Services\AuthService;

// Проверка прав доступа
if (!AuthService::checkRole('admin')) {
    header('Location: /login');
    exit;
}
?>

<div class="container-fluid mt-4">
    <div class="row">
        <div class="col-12">
            <h1 class="mb-4">
                <i class="fas fa-stethoscope"></i> Диагностика системы
            </h1>
            
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Проверка состояния системы</h5>
                    <button class="btn btn-primary" id="runDiagnostics">
                        <i class="fas fa-play"></i> Запустить диагностику
                    </button>
                </div>
                <div class="card-body">
                    <div id="diagnosticsStatus" class="alert alert-info" style="display: none;">
                        <i class="fas fa-spinner fa-spin"></i> Выполняется диагностика...
                    </div>
                    
                    <div id="diagnosticsResults" style="display: none;">
                        <!-- Общая информация -->
                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="card text-center">
                                    <div class="card-body">
                                        <h2 id="healthScore" class="display-4">0</h2>
                                        <p class="text-muted">Health Score</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center">
                                    <div class="card-body">
                                        <h4 id="executionTime">0s</h4>
                                        <p class="text-muted">Время выполнения</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center">
                                    <div class="card-body">
                                        <h4 id="timestamp">-</h4>
                                        <p class="text-muted">Время проверки</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center">
                                    <div class="card-body">
                                        <button class="btn btn-success" id="downloadReport">
                                            <i class="fas fa-download"></i> Скачать отчет
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Детальные результаты -->
                        <div id="diagnosticsDetails"></div>
                    </div>
                    
                    <div id="diagnosticsError" class="alert alert-danger" style="display: none;">
                        <i class="fas fa-exclamation-triangle"></i> <span id="errorMessage"></span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
.diagnostic-section {
    margin-bottom: 2rem;
}

.diagnostic-section h3 {
    background: #f8f9fa;
    padding: 1rem;
    margin-bottom: 1rem;
    border-radius: 0.25rem;
}

.diagnostic-item {
    padding: 0.5rem 1rem;
    border-bottom: 1px solid #dee2e6;
}

.diagnostic-item:last-child {
    border-bottom: none;
}

.status-ok { color: #28a745; }
.status-warning { color: #ffc107; }
.status-error { color: #dc3545; }

pre {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 0.25rem;
    overflow-x: auto;
}

.table-responsive {
    max-height: 400px;
    overflow-y: auto;
}
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const runBtn = document.getElementById('runDiagnostics');
    const statusDiv = document.getElementById('diagnosticsStatus');
    const resultsDiv = document.getElementById('diagnosticsResults');
    const errorDiv = document.getElementById('diagnosticsError');
    const detailsDiv = document.getElementById('diagnosticsDetails');
    
    let diagnosticsData = null;
    
    runBtn.addEventListener('click', function() {
        runBtn.disabled = true;
        statusDiv.style.display = 'block';
        resultsDiv.style.display = 'none';
        errorDiv.style.display = 'none';
        
        fetch('/api/admin/diagnostics/run', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                diagnosticsData = data.data;
                displayResults(data.data);
            } else {
                throw new Error(data.message || 'Неизвестная ошибка');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('errorMessage').textContent = error.message;
            errorDiv.style.display = 'block';
        })
        .finally(() => {
            runBtn.disabled = false;
            statusDiv.style.display = 'none';
        });
    });
    
    function displayResults(data) {
        // Общая информация
        document.getElementById('healthScore').textContent = data.health_score || 0;
        document.getElementById('healthScore').className = getHealthScoreClass(data.health_score);
        document.getElementById('executionTime').textContent = (data.execution_time || 0).toFixed(2) + 's';
        document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString('ru-RU');
        
        // Детальные результаты
        detailsDiv.innerHTML = '';
        
        if (data.diagnostics) {
            for (const [key, section] of Object.entries(data.diagnostics)) {
                detailsDiv.appendChild(createSectionElement(key, section));
            }
        }
        
        resultsDiv.style.display = 'block';
    }
    
    function createSectionElement(key, section) {
        const div = document.createElement('div');
        div.className = 'diagnostic-section';
        
        // Заголовок секции
        const title = document.createElement('h3');
        title.innerHTML = section.title || key;
        if (section.status) {
            title.innerHTML += ' ' + section.status;
        }
        div.appendChild(title);
        
        // Содержимое секции
        const content = document.createElement('div');
        content.className = 'diagnostic-content';
        
        // Обычные данные
        if (section.data) {
            for (const [dataKey, value] of Object.entries(section.data)) {
                const item = document.createElement('div');
                item.className = 'diagnostic-item';
                item.innerHTML = `<strong>${dataKey}:</strong> ${formatValue(value)}`;
                content.appendChild(item);
            }
        }
        
        // Информация
        if (section.info) {
            for (const [infoKey, value] of Object.entries(section.info)) {
                const item = document.createElement('div');
                item.className = 'diagnostic-item';
                item.innerHTML = `<strong>${infoKey}:</strong> ${formatValue(value)}`;
                content.appendChild(item);
            }
        }
        
        // Проверки
        if (section.checks) {
            const checksDiv = document.createElement('div');
            checksDiv.className = 'mt-3';
            
            for (const [checkKey, check] of Object.entries(section.checks)) {
                const item = document.createElement('div');
                item.className = 'diagnostic-item';
                
                if (typeof check === 'object' && check !== null) {
                    const status = check.check ? '✅' : '❌';
                    const current = check.current || check.value || '';
                    const required = check.required || '';
                    item.innerHTML = `<strong>${checkKey}:</strong> ${current} ${status} (требуется: ${required})`;
                    
                    if (check.status) {
                        item.innerHTML += ` ${check.status}`;
                    }
                    if (check.error) {
                        item.innerHTML += ` <span class="text-danger">${check.error}</span>`;
                    }
                } else {
                    item.innerHTML = `<strong>${checkKey}:</strong> ${check}`;
                }
                
                checksDiv.appendChild(item);
            }
            
            content.appendChild(checksDiv);
        }
        
        // Расширения (для PHP)
        if (section.extensions) {
            const extDiv = document.createElement('div');
            extDiv.className = 'mt-3';
            extDiv.innerHTML = '<h5>Расширения PHP:</h5>';
            
            for (const [ext, enabled] of Object.entries(section.extensions)) {
                const span = document.createElement('span');
                span.className = 'badge mr-2 mb-2 ' + (enabled ? 'badge-success' : 'badge-danger');
                span.textContent = ext;
                extDiv.appendChild(span);
            }
            
            content.appendChild(extDiv);
        }
        
        // Таблицы (для БД)
        if (section.tables && Array.isArray(section.tables)) {
            const tableDiv = document.createElement('div');
            tableDiv.className = 'mt-3';
            tableDiv.innerHTML = '<h5>Таблицы базы данных:</h5>';
            
            const table = document.createElement('table');
            table.className = 'table table-sm table-striped';
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Таблица</th>
                        <th>Строк</th>
                        <th>Размер</th>
                        <th>Engine</th>
                    </tr>
                </thead>
                <tbody>
                    ${section.tables.map(t => `
                        <tr>
                            <td>${t.TABLE_NAME}</td>
                            <td>${formatNumber(t.TABLE_ROWS)}</td>
                            <td>${t.size_mb} MB</td>
                            <td>${t.ENGINE}</td>
                        </tr>
                    `).join('')}
                </tbody>
            `;
            
            const tableWrapper = document.createElement('div');
            tableWrapper.className = 'table-responsive';
            tableWrapper.appendChild(table);
            tableDiv.appendChild(tableWrapper);
            
            content.appendChild(tableDiv);
        }
        
        // Статистика
        if (section.stats) {
            const statsDiv = document.createElement('div');
            statsDiv.className = 'mt-3';
            statsDiv.innerHTML = '<h5>Статистика:</h5>';
            statsDiv.innerHTML += '<pre>' + JSON.stringify(section.stats, null, 2) + '</pre>';
            content.appendChild(statsDiv);
        }
        
        // Ошибки
        if (section.error) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'alert alert-danger mt-3';
            errorDiv.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${section.error}`;
            content.appendChild(errorDiv);
        }
        
        // Последние ошибки (для логов)
        if (section.last_errors && Array.isArray(section.last_errors)) {
            const errorsDiv = document.createElement('div');
            errorsDiv.className = 'mt-3';
            errorsDiv.innerHTML = '<h5>Последние ошибки:</h5>';
            
            if (section.last_errors.length > 0) {
                const list = document.createElement('ul');
                section.last_errors.forEach(error => {
                    const li = document.createElement('li');
                    li.innerHTML = `<span class="text-danger">[${error.level}]</span> ${error.message} <small class="text-muted">${error.created_at}</small>`;
                    list.appendChild(li);
                });
                errorsDiv.appendChild(list);
            } else {
                errorsDiv.innerHTML += '<p class="text-success">Нет ошибок</p>';
            }
            
            content.appendChild(errorsDiv);
        }
        
        div.appendChild(content);
        return div;
    }
    
    function formatValue(value) {
        if (value === null || value === undefined) {
            return '<span class="text-muted">N/A</span>';
        }
        if (typeof value === 'boolean') {
            return value ? '✅' : '❌';
        }
        if (typeof value === 'object') {
            return '<pre>' + JSON.stringify(value, null, 2) + '</pre>';
        }
        return value;
    }
    
    function formatNumber(num) {
        return parseInt(num).toLocaleString('ru-RU');
    }
    
    function getHealthScoreClass(score) {
        if (score >= 80) return 'display-4 text-success';
        if (score >= 60) return 'display-4 text-warning';
        return 'display-4 text-danger';
    }
    
    // Скачивание отчета
    document.getElementById('downloadReport').addEventListener('click', function() {
        if (!diagnosticsData) return;
        
        const dataStr = JSON.stringify(diagnosticsData, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `vdestor-diagnostics-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    });
});
</script>