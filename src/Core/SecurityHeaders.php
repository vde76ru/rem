<?php
namespace App\Core;

/**
 * Управление заголовками безопасности
 */
class SecurityHeaders
{
    public static function set(): void
    {
        if (headers_sent()) {
            return;
        }

        $headers = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()'
        ];

        foreach ($headers as $name => $value) {
            header("{$name}: {$value}");
        }

        // HSTS только для HTTPS
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }

        // CSP
        $csp = [
            "default-src" => "'self'",
            "script-src" => "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
            "style-src" => "'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src" => "'self' data: https:",
            "font-src" => "'self' https://fonts.gstatic.com data:",
            "connect-src" => "'self'",
            "object-src" => "'none'",
            "base-uri" => "'self'"
        ];

        $cspString = implode('; ', array_map(
            fn($k, $v) => "{$k} {$v}",
            array_keys($csp),
            $csp
        ));

        header("Content-Security-Policy: {$cspString}");
    }
}