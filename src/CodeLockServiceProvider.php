<?php

namespace Rasel\CodeLock;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Rasel\CodeLock\Commands\ActivateCommand;
use Rasel\CodeLock\Commands\CheckCommand;
use Rasel\CodeLock\Commands\DeactivateCommand;
use Rasel\CodeLock\Commands\GenerateIntegrityManifestCommand;
use Rasel\CodeLock\Commands\HeartbeatCommand;
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
                HeartbeatCommand::class,
                GenerateIntegrityManifestCommand::class,
            ]);

            // Register Heartbeat Task in Scheduler
            $this->registerSchedule();
        }

        // 3. Register Global HTTP Middleware
        if (config('codelock.auto_register_middleware', true)) {
            if ($this->app->bound(HttpKernel::class)) {
                $kernel = $this->app->make(HttpKernel::class);
                if (method_exists($kernel, 'hasMiddleware') && !$kernel->hasMiddleware(EnsureLicensed::class)) {
                    $kernel->pushMiddleware(EnsureLicensed::class);
                }
            }
        }

        // 4. Register Middleware Aliases
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('codelock', EnsureLicensed::class);
        $router->aliasMiddleware('codelock.verify', EnsureLicensed::class);

        // 5. Register Recovery Endpoint (POST only with rate limiting and CSRF protection)
        $router->post('codelock/recover', [
            \Rasel\CodeLock\Http\Controllers\RecoveryController::class,
            'recover',
        ])->name('codelock.recover');
    }

    /**
     * Register periodic license heartbeat synchronization in the application scheduler.
     */
    protected function registerSchedule(): void
    {
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            // Prevent duplicate task registrations
            foreach ($schedule->events() as $event) {
                if (is_string($event->command) && str_contains($event->command, 'codelock:heartbeat')) {
                    return;
                }
            }

            $intervalHours = (int) config('codelock.heartbeat_interval', 6);
            $event = $schedule->command('codelock:heartbeat');

            match ($intervalHours) {
                1 => $event->hourly(),
                2 => $event->everyTwoHours(),
                3 => $event->everyThreeHours(),
                4 => $event->everyFourHours(),
                6 => $event->everySixHours(),
                12 => $event->twiceDaily(0, 12),
                24 => $event->daily(),
                default => ($intervalHours > 0 && $intervalHours < 24 && (24 % $intervalHours === 0))
                    ? $event->cron("0 */{$intervalHours} * * *")
                    : $event->cron("0 */" . max(1, min(24, $intervalHours)) . " * * *"),
            };

            $event->withoutOverlapping(60)
                  ->name('codelock-heartbeat')
                  ->when(function () {
                      if (!config('codelock.enabled', true)) {
                          return false;
                      }
                      $storage = app(LicenseStorage::class);
                      return $storage->hasCertificate();
                  });
        });
    }
}

