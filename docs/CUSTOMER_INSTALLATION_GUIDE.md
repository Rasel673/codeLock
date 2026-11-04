# Customer Installation & Integration Guide

Welcome to the **CodeLock Protected Application Setup Guide**. This document walks you through integrating and activating your commercial software license.

---

## 1. System Requirements

Before proceeding, verify your hosting environment satisfies these requirements:

- **PHP:** Version 8.2 or 8.3.
- **Required PHP Extensions:**
  - `ext-sodium` (Critical: required for Ed25519 cryptographic verification)
  - `ext-mbstring`
  - `ext-json`
  - `ext-curl`
  - `ext-bcmath`
- **Framework:** Laravel 10.x, 11.x, or 12.x.
- **File System:** Writable `storage/app/` directory (for encrypted certificate caching).
- **Outbound Connectivity:** HTTPS (port 443) outbound access to the licensing server.

---

## 2. Step-by-Step Installation

### Step 1: Configure Private Composer Access
Add the private repository to your `composer.json` using the deploy token supplied by your software vendor:

1. Configure authentication:
   ```bash
   composer config --auth github-oauth.github.com "<YOUR_VENDOR_PROVIDED_TOKEN>"
   ```
2. In `composer.json`, register the repository:
   ```json
   "repositories": [
       {
           "type": "vcs",
           "url": "https://github.com/your-organization/codelock-laravel.git"
       }
   ]
   ```
3. Install package:
   ```bash
   composer require rasel/codelock-laravel
   ```

### Step 2: Publish Configuration & Views
Publish the CodeLock configuration file and customizable lock screen views:
```bash
php artisan vendor:publish --tag=codelock-config
php artisan vendor:publish --tag=codelock-views
```

This creates:
- `config/codelock.php`
- `resources/views/vendor/codelock/locked.blade.php`

### Step 3: Configure Environment Variables
Add your commercial licensing credentials to your application's `.env` file:

```dotenv
# ==============================================================================
# CODELOCK COMMERCIAL LICENSE CONFIGURATION
# ==============================================================================
CODELOCK_ENABLED=true
CODELOCK_SERVER_URL=https://license.yourdomain.com
CODELOCK_PRODUCT_ID=PROD-YOUR-PRODUCT
CODELOCK_LICENSE_KEY=CLK-XXXX-XXXX-XXXX-XXXX
CODELOCK_PUBLIC_KEY="YOUR_BASE64_ED25519_PUBLIC_KEY"

# Operational Policies
CODELOCK_OFFLINE_GRACE_PERIOD=7
CODELOCK_HEARTBEAT_INTERVAL=24
CODELOCK_CONTACT_EMAIL=support@yourdomain.com
CODELOCK_CONTACT_URL=https://yourdomain.com/support
```

### Step 4: Protect Application Routes
Apply the `codelock` middleware to protect your application routes in `routes/web.php` or `routes/api.php`:

```php
use Illuminate\Support\Facades\Route;

// Protected Business Routes
Route::middleware(['web', 'codelock'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::resource('invoices', InvoiceController::class);
    Route::resource('projects', ProjectController::class);
});

// Protected API Routes
Route::middleware(['api', 'codelock'])->prefix('v1')->group(function () {
    Route::get('/analytics', [AnalyticsApiController::class, 'index']);
});
```

*(Note: Unprotected routes such as public landing pages, login screens, and health checks will remain accessible even if the license requires attention).*

### Step 5: Activate Your License
Run the activation command from your application terminal:
```bash
php artisan codelock:activate CLK-XXXX-XXXX-XXXX-XXXX
```

*Expected output:*
```text
Connecting to license server at [https://license.yourdomain.com]...
✓ Cryptographic signature verified successfully (Ed25519).
✓ License certificate persisted to [storage/app/.codelock.lic].
✓ Application access enabled for domain [yourdomain.com].
Status: ACTIVE
```

### Step 6: Verify Active Status
Inspect the cryptographic status of your installation:
```bash
php artisan codelock:status
```

*Sample status output:*
```text
+-----------------------+---------------------------------------+
| Metric                | Value                                 |
+-----------------------+---------------------------------------+
| License Key           | CLK-XXXX-XXXX-XXXX-XXXX               |
| Status                | ACTIVE                                |
| Valid                 | YES                                   |
| Allowed Domains       | yourdomain.com, www.yourdomain.com    |
| Offline Grace Remain  | 7 days                                |
| Entitlements          | Tier: Enterprise, Multi-Tenant: true  |
| Next Heartbeat Due    | 24 hours                              |
+-----------------------+---------------------------------------+
```

### Step 7: Configure Scheduled Background Sync
Ensure the Laravel scheduler is configured on your server or cPanel hosting:
```bash
* * * * * cd /path/to/your/application && php artisan schedule:run >> /dev/null 2>&1
```
CodeLock automatically checks in with the licensing authority once per day to ensure license continuity and download renewals.

