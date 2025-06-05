<?php
namespace App\Controllers;

use App\Core\Layout;
use App\Services\AuthService;

class AdminController extends BaseController
{
    /**
     * GET /admin - Главная страница админ панели
     */
    public function indexAction(): void
    {
        if (!AuthService::checkRole('admin')) {
            header('Location: /login');
            exit;
        }
        $user = AuthService::user();
        Layout::render('admin/index', ['user' => $user]);
    }

    /**
     * GET /admin/diagnostics - Диагностика системы
     */
    public function diagnosticsAction(): void
    {
        if (!AuthService::checkRole('admin')) {
            header('Location: /login');
            exit;
        }
        $user = AuthService::user();
        Layout::render('admin/diagnost', ['user' => $user]);
    }
    
    public function documentationAction(): void
    {
        if (!AuthService::checkRole('admin')) {
            header('Location: /login');
            exit;
        }
        $user = AuthService::user();
        Layout::render('admin/documentation', ['user' => $user]);
    }
}