<?php

namespace Rasel\CodeLock;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Rasel\CodeLock\Commands\ActivateCommand;
use Rasel\CodeLock\Commands\CheckCommand;
use Rasel\CodeLock\Commands\DeactivateCommand;
use Rasel\CodeLock\Commands\GenerateIntegrityManifestCommand;
use Rasel\CodeLock\Commands\InstallCommand;
use Rasel\CodeLock\Commands\RefreshCommand;
use Rasel\CodeLock\Commands\StatusCommand;
use Rasel\CodeLock\Middleware\EnsureLicensed;
use Rasel\CodeLock\Storage\LicenseStorage;

class CodeLockServiceProvider extends ServiceProvider
{
    /**
     * Register any package services and bindings.
     */
    public function register(): void
    {
        // 1. Merge default package configuration
        $this->mergeConfigFrom(
            __DIR__ . '/../config/codelock.php',
            'codelock'
        );

        // 2. Register Singletons
        $this->app->singleton(LicenseStorage::class, function ($app) {
            return new LicenseStorage();
        });

        $this->app->singleton(LicenseVerifier::class, function ($app) {
            return new LicenseVerifier(
                $app->make(LicenseStorage::class)
            );
        });

        $this->app->singleton(LicenseClient::class, function ($app) {
            return new LicenseClient();
        });

        $this->app->singleton(IntegrityMonitor::class, function ($app) {
            return new IntegrityMonitor(
                storage: $app->make(LicenseStorage::class)
            );
        });

        $this->app->singleton(SecurityEventReporter::class, function ($app) {
            return new SecurityEventReporter(
                $app->make(LicenseClient::class),
                $app->make(LicenseStorage::class)
            );
        });

        $this->app->singleton(LicenseHeartbeat::class, function ($app) {
            return new LicenseHeartbeat(
                $app->make(LicenseStorage::class),
                $app->make(LicenseClient::class),
                $app->make(LicenseVerifier::class),
                $app->make(SecurityEventReporter::class),
                $app->make(IntegrityMonitor::class)
            );
        });

        $this->app->singleton(LicenseManager::class, function ($app) {
            return new LicenseManager(
                $app->make(LicenseStorage::class),
                $app->make(LicenseVerifier::class),
                $app->make(LicenseClient::class),
                $app->make(IntegrityMonitor::class),
                $app->make(SecurityEventReporter::class),
                $app->make(LicenseHeartbeat::class)
            );
        });

        $this->app->alias(LicenseManager::class, 'codelock');
    }

    /**
     * Bootstrap any application services, views, commands, and middleware.
     */
    public function boot(): void
    {
        // 1. Load Package Views
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'codelock');

        // 2. Setup Publishing
        if ($this->app->runningInConsole()) {
            // Config publish
            $this->publishes([
                __DIR__ . '/../config/codelock.php' => config_path('codelock.php'),
            ], 'codelock-config');

            // Views publish
            $this->publishes([
                __DIR__ . '/../resources/views' => resource_path('views/vendor/codelock'),
            ], 'codelock-views');

            // Register Artisan Commands
            $this->commands([
                InstallCommand::class,
                ActivateCommand::class,
                StatusCommand::class,
                CheckCommand::class,
                DeactivateCommand::class,
                RefreshCommand::class,
                GenerateIntegrityManifestCommand::class,
            ]);
        }

        // 3. Register Middleware Aliases
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('codelock', EnsureLicensed::class);
        $router->aliasMiddleware('codelock.verify', EnsureLicensed::class);

        // 4. Register Recovery Endpoint (POST only with rate limiting and CSRF protection)
        $router->post('codelock/recover', [
            \Rasel\CodeLock\Http\Controllers\RecoveryController::class,
            'recover',
        ])->name('codelock.recover');
    }
}

