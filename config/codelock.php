<?php

return [

    /*
    |--------------------------------------------------------------------------
    | CodeLock Master Switch
    |--------------------------------------------------------------------------
    |
    | When enabled, CodeLock will verify license signatures, domain legitimacy,
    | expiration dates, and remote status before allowing requests to proceed.
    |
    */
    'enabled' => env('CODELOCK_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Product Identifier
    |--------------------------------------------------------------------------
    |
    | The unique product code configured on your CodeLock license server.
    | The package will verify that signed licenses match this product.
    |
    */
    'product_id' => env('CODELOCK_PRODUCT_ID', ''),

    /*
    |--------------------------------------------------------------------------
    | License Server Endpoint
    |--------------------------------------------------------------------------
    |
    | The full base URL of your private CodeLock license server.
    |
    */
    'license_server_url' => env('CODELOCK_SERVER_URL', 'https://license.yourdomain.com'),

    /*
    |--------------------------------------------------------------------------
    | License Key
    |--------------------------------------------------------------------------
    |
    | The customer's assigned license key (e.g., CLK-XXXX-XXXX-XXXX-XXXX).
    | Can also be loaded dynamically from the storage file or database.
    |
    */
    'license_key' => env('CODELOCK_LICENSE_KEY', ''),

    /*
    |--------------------------------------------------------------------------
    | Cryptographic Public Key (Ed25519)
    |--------------------------------------------------------------------------
    |
    | The 32-byte Ed25519 public key (Base64-encoded) corresponding to your
    | server's private signing key. Hardcoded or distributed in environment.
    |
    */
    'public_key' => env('CODELOCK_PUBLIC_KEY', ''),

    /*
    |--------------------------------------------------------------------------
    | Installation Identifier
    |--------------------------------------------------------------------------
    |
    | Unique instance fingerprint for this specific deployment. If left null,
    | CodeLock computes a stable fingerprint from machine and environment metadata.
    |
    */
    'installation_id' => env('CODELOCK_INSTALLATION_ID', null),

    /*
    |--------------------------------------------------------------------------
    | Offline Grace Period (Days)
    |--------------------------------------------------------------------------
    |
    | Number of days the software will continue operating if the remote
    | license server becomes unreachable during heartbeat synchronization.
    |
    */
    'offline_grace_period' => (int) env('CODELOCK_OFFLINE_GRACE_PERIOD', 7),

    /*
    |--------------------------------------------------------------------------
    | Heartbeat Interval (Hours)
    |--------------------------------------------------------------------------
    |
    | How often the client application should check in with the central
    | server to synchronize license state and remote lock policies.
    |
    */
    'heartbeat_interval' => (int) env('CODELOCK_HEARTBEAT_INTERVAL', 24),

    /*
    |--------------------------------------------------------------------------
    | Commercial Support & Contact Information
    |--------------------------------------------------------------------------
    |
    | Contact details displayed on the license restriction screen when an
    | installation is locked, expired, or pending administrative approval.
    |
    */
    'contact_email' => env('CODELOCK_CONTACT_EMAIL', 'support@yourdomain.com'),
    'contact_url' => env('CODELOCK_CONTACT_URL', 'https://yourdomain.com/support'),

    /*
    |--------------------------------------------------------------------------
    | License Storage Configuration
    |--------------------------------------------------------------------------
    |
    | File path where the local encrypted license certificate and remote status
    | cache are stored. By default, stored securely inside storage/app/.
    |
    */
    'storage_path' => env('CODELOCK_STORAGE_PATH', storage_path('app/.codelock.lic')),
    'status_cache_path' => env('CODELOCK_STATUS_CACHE_PATH', storage_path('app/.codelock.status')),

    /*
    |--------------------------------------------------------------------------
    | Local Development Bypass
    |--------------------------------------------------------------------------
    |
    | When true, requests from localhost, 127.0.0.1, or .test domains bypass
    | domain restriction checks (useful for developers testing locally).
    | Should always be false in production environments.
    |
    */
    'allow_local' => env('CODELOCK_ALLOW_LOCAL', false),

    /*
    |--------------------------------------------------------------------------
    | Excluded Routes
    |--------------------------------------------------------------------------
    |
    | URIs or patterns that bypass license verification middleware (e.g.,
    | health check probes, webhooks, or license activation endpoints).
    |
    */
    'excluded_paths' => [
        'codelock/*',
        'up',
        'health',
        'healthz',
    ],

    /*
    |--------------------------------------------------------------------------
    | Lock Screen View
    |--------------------------------------------------------------------------
    |
    | The Blade view rendered when license verification fails. You can publish
    | and customize the default template or specify your own custom view name.
    |
    */
    'lock_view' => 'codelock::locked',

    /*
    |--------------------------------------------------------------------------
    | HTTP Client Timeout (Seconds)
    |--------------------------------------------------------------------------
    |
    | Request timeout when communicating with the license server.
    |
    */
    'request_timeout' => (int) env('CODELOCK_TIMEOUT', 10),

    /*
    |--------------------------------------------------------------------------
    | CodeLock Integrity Monitoring
    |--------------------------------------------------------------------------
    |
    | Cryptographic file integrity monitoring to detect modifications to
    | designated package enforcement files. Excludes mutable cache & storage.
    |
    */
    'integrity' => [
        'enabled' => env('CODELOCK_INTEGRITY_ENABLED', true),
        'manifest_path' => env('CODELOCK_MANIFEST_PATH', null),
        'cache_ttl' => (int) env('CODELOCK_INTEGRITY_CACHE_TTL', 3600),
        'stochastic_rate' => (int) env('CODELOCK_INTEGRITY_STOCHASTIC_RATE', 5),
    ],

];

