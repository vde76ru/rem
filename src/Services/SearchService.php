<?php
namespace App\Services;

use App\Core\Database;
use App\Core\Logger;
use App\Core\Cache;
use OpenSearch\ClientBuilder;

class SearchService
{
    private static ?\OpenSearch\Client $client = null;
    private static array $keyboardLayout = [
        // EN -> RU
        'q' => 'й', 'w' => 'ц', 'e' => 'у', 'r' => 'к', 't' => 'е', 'y' => 'н', 'u' => 'г', 'i' => 'ш', 'o' => 'щ', 'p' => 'з',
        'a' => 'ф', 's' => 'ы', 'd' => 'в', 'f' => 'а', 'g' => 'п', 'h' => 'р', 'j' => 'о', 'k' => 'л', 'l' => 'д',
        'z' => 'я', 'x' => 'ч', 'c' => 'с', 'v' => 'м', 'b' => 'и', 'n' => 'т', 'm' => 'ь',
        // RU -> EN
        'й' => 'q', 'ц' => 'w', 'у' => 'e', 'к' => 'r', 'е' => 't', 'н' => 'y', 'г' => 'u', 'ш' => 'i', 'щ' => 'o', 'з' => 'p',
        'ф' => 'a', 'ы' => 's', 'в' => 'd', 'а' => 'f', 'п' => 'g', 'р' => 'h', 'о' => 'j', 'л' => 'k', 'д' => 'l',
        'я' => 'z', 'ч' => 'x', 'с' => 'c', 'м' => 'v', 'и' => 'b', 'т' => 'n', 'ь' => 'm'
    ];

    /**
     * Главный метод поиска
     */
    public static function search(array $params): array
    {
        $requestId = uniqid('search_', true);
        $startTime = microtime(true);

        Logger::info("🔍 [$requestId] Search started", ['params' => $params]);

        try {
            $params = self::validateParams($params);

            // Если нет поискового запроса, используем MySQL для листинга
            if (empty($params['q']) || strlen(trim($params['q'])) === 0) {
                Logger::info("📋 [$requestId] Empty query, using MySQL for listing");
                $result = self::searchViaMySQL($params);
                return [
                    'success' => true,
                    'data' => $result
                ];
            }

            // Проверяем доступность OpenSearch
            if (self::isOpenSearchAvailable()) {
                Logger::debug("✅ [$requestId] Using OpenSearch");
                try {
                    $result = self::performOpenSearch($params, $requestId);
                    $duration = round((microtime(true) - $startTime) * 1000, 2);
                    Logger::info("✅ [$requestId] OpenSearch completed in {$duration}ms");
                    return [
                        'success' => true,
                        'data' => $result
                    ];
                } catch (\Exception $e) {
                    Logger::warning("⚠️ [$requestId] OpenSearch failed, falling back to MySQL", [
                        'error' => $e->getMessage()
                    ]);
                }
            }

            // MySQL поиск как fallback
            $result = self::searchViaMySQL($params);
            return [
                'success' => true,
                'data' => $result
            ];

        } catch (\Exception $e) {
            Logger::error("❌ [$requestId] Search failed", [
                'error' => $e->getMessage()
            ]);

            // Возвращаем пустой результат при ошибке
            return [
                'success' => false,
                'error' => 'Search service temporarily unavailable',
                'error_code' => 'SERVICE_UNAVAILABLE',
                'data' => [
                    'products' => [],
                    'total' => 0,
                    'page' => $params['page'] ?? 1,
                    'limit' => $params['limit'] ?? 20
                ]
            ];
        }
    }

    /**
     * Поиск через MySQL с поддержкой конвертации раскладки
     */
    private static function searchViaMySQL(array $params): array
    {
        $query = $params['q'] ?? '';
        $page = $params['page'];
        $limit = $params['limit'];
        $offset = ($page - 1) * $limit;

        try {
            $pdo = Database::getConnection();

            if (empty($query)) {
                // Простой листинг товаров
                $sql = "SELECT SQL_CALC_FOUND_ROWS 
                        p.product_id, p.external_id, p.sku, p.name, p.description,
                        p.brand_id, p.series_id, p.unit, p.min_sale, p.weight, p.dimensions,
                        b.name as brand_name, s.name as series_name,
                        1 as relevance_score
                        FROM products p
                        LEFT JOIN brands b ON p.brand_id = b.brand_id
                        LEFT JOIN series s ON p.series_id = s.series_id
                        ORDER BY p.product_id DESC
                        LIMIT :limit OFFSET :offset";

                $stmt = $pdo->prepare($sql);
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
                $stmt->execute();

            } else {
                // Генерируем варианты запроса
                $searchVariants = self::generateSearchVariants($query);
                
                // Строим SQL с учетом вариантов
                $whereParts = [];
                $params = [];
                
                foreach ($searchVariants as $idx => $variant) {
                    $whereParts[] = "(
                        p.external_id = :exact{$idx} OR
                        p.sku = :exact{$idx} OR
                        p.external_id LIKE :prefix{$idx} OR
                        p.sku LIKE :prefix{$idx} OR
                        p.name LIKE :search{$idx} OR
                        p.description LIKE :search{$idx} OR
                        b.name LIKE :search{$idx}
                    )";
                    
                    $params["exact{$idx}"] = $variant;
                    $params["prefix{$idx}"] = $variant . '%';
                    $params["search{$idx}"] = '%' . $variant . '%';
                }

                $sql = "SELECT SQL_CALC_FOUND_ROWS 
                        p.product_id, p.external_id, p.sku, p.name, p.description,
                        p.brand_id, p.series_id, p.unit, p.min_sale, p.weight, p.dimensions,
                        b.name as brand_name, s.name as series_name,
                        CASE 
                            WHEN p.external_id = :score_exact THEN 1000
                            WHEN p.sku = :score_exact THEN 900
                            WHEN p.external_id LIKE :score_prefix THEN 100
                            WHEN p.sku LIKE :score_prefix THEN 90
                            WHEN p.name = :score_exact THEN 80
                            WHEN p.name LIKE :score_prefix THEN 50
                            WHEN p.name LIKE :score_search THEN 30
                            ELSE 1
                        END as relevance_score
                        FROM products p
                        LEFT JOIN brands b ON p.brand_id = b.brand_id
                        LEFT JOIN series s ON p.series_id = s.series_id
                        WHERE " . implode(' OR ', $whereParts) . "
                        ORDER BY relevance_score DESC, p.name ASC
                        LIMIT :limit OFFSET :offset";

                $stmt = $pdo->prepare($sql);
                
                // Привязываем все параметры
                foreach ($params as $key => $value) {
                    $stmt->bindValue(':' . $key, $value, \PDO::PARAM_STR);
                }
                
                // Параметры для скоринга
                $stmt->bindValue(':score_exact', $query, \PDO::PARAM_STR);
                $stmt->bindValue(':score_prefix', $query . '%', \PDO::PARAM_STR);
                $stmt->bindValue(':score_search', '%' . $query . '%', \PDO::PARAM_STR);
                
                // Пагинация
                $stmt->bindValue(':limit', $limit, \PDO::PARAM_INT);
                $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
                
                $stmt->execute();
            }

            $products = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            $total = $pdo->query("SELECT FOUND_ROWS()")->fetchColumn();

            return [
                'products' => $products,
                'total' => (int)$total,
                'page' => $page,
                'limit' => $limit,
                'source' => 'mysql',
                'search_variants' => $searchVariants ?? []
            ];

        } catch (\Exception $e) {
            Logger::error('MySQL search failed', ['error' => $e->getMessage()]);
            throw $e;
        }
    }

    /**
     * Поиск через OpenSearch
     */
    private static function performOpenSearch(array $params, string $requestId): array
    {
        $client = self::getClient();
        
        $body = [
            'size' => $params['limit'],
            'from' => ($params['page'] - 1) * $params['limit'],
            'track_total_hits' => true
        ];

        if (!empty($params['q'])) {
            $query = trim($params['q']);
            $searchVariants = self::generateSearchVariants($query);
            
            $shouldClauses = [];
            
            foreach ($searchVariants as $variant) {
                // Точное совпадение артикула
                $shouldClauses[] = [
                    'term' => ['external_id.keyword' => ['value' => $variant, 'boost' => 1000]]
                ];
                $shouldClauses[] = [
                    'term' => ['sku.keyword' => ['value' => $variant, 'boost' => 900]]
                ];
                
                // Префиксный поиск по артикулам
                $shouldClauses[] = [
                    'prefix' => ['external_id' => ['value' => $variant, 'boost' => 100]]
                ];
                
                // Поиск по названию
                $shouldClauses[] = [
                    'match_phrase' => [
                        'name' => ['query' => $variant, 'boost' => 200]
                    ]
                ];
                $shouldClauses[] = [
                    'match' => [
                        'name' => ['query' => $variant, 'boost' => 50]
                    ]
                ];
                
                // Поиск по бренду
                $shouldClauses[] = [
                    'match' => [
                        'brand_name' => ['query' => $variant, 'boost' => 80]
                    ]
                ];
                
                // Автодополнение
                $shouldClauses[] = [
                    'match' => [
                        'name.autocomplete' => ['query' => $variant, 'boost' => 30]
                    ]
                ];
                
                // Общий поиск
                $shouldClauses[] = [
                    'match' => [
                        'search_text' => ['query' => $variant, 'boost' => 20]
                    ]
                ];
            }

            $body['query'] = [
                'bool' => [
                    'should' => $shouldClauses,
                    'minimum_should_match' => 1
                ]
            ];

            // Подсветка результатов
            $body['highlight'] = [
                'fields' => [
                    'name' => ['number_of_fragments' => 0],
                    'external_id' => ['number_of_fragments' => 0],
                    'brand_name' => ['number_of_fragments' => 0]
                ],
                'pre_tags' => ['<mark>'],
                'post_tags' => ['</mark>']
            ];

        } else {
            $body['query'] = ['match_all' => new \stdClass()];
        }

        // Сортировка
        switch ($params['sort']) {
            case 'name':
                $body['sort'] = [['name.keyword' => 'asc']];
                break;
            case 'external_id':
                $body['sort'] = [['external_id.keyword' => 'asc']];
                break;
            case 'popularity':
                $body['sort'] = [['popularity_score' => 'desc']];
                break;
            default:
                if (!empty($params['q'])) {
                    $body['sort'] = [
                        ['_score' => 'desc'],
                        ['has_stock' => 'desc'],
                        ['popularity_score' => 'desc']
                    ];
                } else {
                    $body['sort'] = [['product_id' => 'desc']];
                }
        }

        Logger::debug("[$requestId] OpenSearch query", [
            'body' => json_encode($body, JSON_PRETTY_PRINT)
        ]);

        try {
            $response = $client->search([
                'index' => 'products_current',
                'body' => $body
            ]);

            $products = [];
            foreach ($response['hits']['hits'] ?? [] as $hit) {
                $product = $hit['_source'];
                $product['_score'] = $hit['_score'] ?? 0;
                
                if (isset($hit['highlight'])) {
                    $product['_highlight'] = $hit['highlight'];
                }
                
                $products[] = $product;
            }

            $total = $response['hits']['total']['value'] ?? 0;

            return [
                'products' => $products,
                'total' => $total,
                'page' => $params['page'],
                'limit' => $params['limit'],
                'source' => 'opensearch',
                'max_score' => $response['hits']['max_score'] ?? 0,
                'search_variants' => $searchVariants ?? []
            ];

        } catch (\Exception $e) {
            Logger::error("[$requestId] OpenSearch failed", ['error' => $e->getMessage()]);
            throw $e;
        }
    }

    /**
     * Генерация вариантов поискового запроса
     */
    private static function generateSearchVariants(string $query): array
    {
        $variants = [$query];

        // 1. Конвертация раскладки клавиатуры
        $converted = self::convertKeyboardLayout($query);
        if ($converted !== $query) {
            $variants[] = $converted;
        }

        // 2. Транслитерация RU->EN
        $transliterated = self::transliterate($query);
        if ($transliterated !== $query && !in_array($transliterated, $variants)) {
            $variants[] = $transliterated;
        }

        // 3. Нормализация (удаление пробелов и спецсимволов)
        $normalized = preg_replace('/[^a-zA-Z0-9а-яА-Я]/u', '', $query);
        if ($normalized !== $query && !in_array($normalized, $variants)) {
            $variants[] = $normalized;
        }

        return array_unique($variants);
    }

    /**
     * Конвертация раскладки клавиатуры
     */
    private static function convertKeyboardLayout(string $text): string
    {
        $result = '';
        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        
        foreach ($chars as $char) {
            $lower = mb_strtolower($char);
            if (isset(self::$keyboardLayout[$lower])) {
                $converted = self::$keyboardLayout[$lower];
                // Сохраняем регистр
                if ($char !== $lower) {
                    $converted = mb_strtoupper($converted);
                }
                $result .= $converted;
            } else {
                $result .= $char;
            }
        }
        
        return $result;
    }

    /**
     * Транслитерация RU -> EN
     */
    private static function transliterate(string $text): string
    {
        $rules = [
            'а' => 'a', 'б' => 'b', 'в' => 'v', 'г' => 'g', 'д' => 'd',
            'е' => 'e', 'ё' => 'e', 'ж' => 'zh', 'з' => 'z', 'и' => 'i',
            'й' => 'y', 'к' => 'k', 'л' => 'l', 'м' => 'm', 'н' => 'n',
            'о' => 'o', 'п' => 'p', 'р' => 'r', 'с' => 's', 'т' => 't',
            'у' => 'u', 'ф' => 'f', 'х' => 'h', 'ц' => 'ts', 'ч' => 'ch',
            'ш' => 'sh', 'щ' => 'sch', 'ъ' => '', 'ы' => 'y', 'ь' => '',
            'э' => 'e', 'ю' => 'yu', 'я' => 'ya'
        ];

        $text = mb_strtolower($text);
        return strtr($text, $rules);
    }

    /**
     * Проверка доступности OpenSearch
     */
    private static function isOpenSearchAvailable(): bool
    {
        static $isAvailable = null;
        static $lastCheck = 0;

        // Кеш проверки на 60 секунд
        if ($isAvailable !== null && (time() - $lastCheck) < 60) {
            return $isAvailable;
        }

        try {
            $client = self::getClient();
            $response = $client->ping();
            
            if ($response) {
                $health = $client->cluster()->health(['timeout' => '2s']);
                $isAvailable = in_array($health['status'] ?? 'red', ['green', 'yellow']);
            } else {
                $isAvailable = false;
            }
            
            $lastCheck = time();
            
        } catch (\Exception $e) {
            $isAvailable = false;
            $lastCheck = time();
            Logger::error("OpenSearch check failed", ['error' => $e->getMessage()]);
        }

        return $isAvailable;
    }

    /**
     * Получение клиента OpenSearch
     */
    private static function getClient(): \OpenSearch\Client
    {
        if (self::$client === null) {
            self::$client = ClientBuilder::create()
                ->setHosts(['localhost:9200'])
                ->setRetries(2)
                ->setConnectionParams([
                    'timeout' => 5,
                    'connect_timeout' => 2
                ])
                ->build();
        }
        return self::$client;
    }

    /**
     * Валидация параметров
     */
    private static function validateParams(array $params): array
    {
        return [
            'q' => trim($params['q'] ?? ''),
            'page' => max(1, (int)($params['page'] ?? 1)),
            'limit' => min(100, max(1, (int)($params['limit'] ?? 20))),
            'city_id' => (int)($params['city_id'] ?? 1),
            'sort' => $params['sort'] ?? 'relevance',
            'user_id' => $params['user_id'] ?? null
        ];
    }

    /**
     * Автодополнение
     */
    public static function autocomplete(string $query, int $limit = 10): array
    {
        if (strlen($query) < 2) {
            return [];
        }

        try {
            $client = self::getClient();
            
            $body = [
                'suggest' => [
                    'product-suggest' => [
                        'prefix' => $query,
                        'completion' => [
                            'field' => 'suggest',
                            'size' => $limit,
                            'skip_duplicates' => true
                        ]
                    ]
                ]
            ];

            $response = $client->search([
                'index' => 'products_current',
                'body' => $body
            ]);

            $suggestions = [];
            
            if (isset($response['suggest']['product-suggest'][0]['options'])) {
                foreach ($response['suggest']['product-suggest'][0]['options'] as $option) {
                    $suggestions[] = [
                        'text' => $option['text'],
                        'score' => $option['_score']
                    ];
                }
            }

            return $suggestions;

        } catch (\Exception $e) {
            Logger::warning('Autocomplete failed', ['error' => $e->getMessage()]);
            return [];
        }
    }
}