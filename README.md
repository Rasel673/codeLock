# CodeLock for Laravel (`rasel673/codelock`)

[![Latest Version](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://packagist.org/packages/rasel673/codelock)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-11%20%7C%2012-red.svg)](https://laravel.com)
[![Cryptography](https://img.shields.io/badge/Security-Ed25519-green.svg)](https://ed25519.cr.yp.to/)
[![License](https://img.shields.io/badge/License-Proprietary-darkblue.svg)](#)

**CodeLock** is a high-security, commercial software licensing and anti-piracy package built specifically for the Laravel ecosystem (Laravel 11 and Laravel 12). It protects commercial Laravel software applications, SaaS boilerplates, and self-hosted products distributed to end-customers.

---

## 1. Key Capabilities

- **Ed25519 Cryptographic Signatures**: Hardware-accelerated signature verification ensures license certificates cannot be forged or tampered with even if customer source files are modified.
- **Asymmetric Key Separation**: The client package contains **only** public verification keys. Private signing keys remain strictly isolated on your central licensing server.
- **Automatic Heartbeat Without Cron**: Automatically synchronizes license state with the licensing server when normal website traffic arrives—no cPanel cron jobs, worker daemons, or scheduler configurations required for your customers.
- **cPanel & Shared Hosting Hardened**: Features a dual-driver crypto engine (`ext-sodium` with automatic fallback to `paragonie/sodium_compat`), guaranteeing operation across restrictive cPanel environments where native extensions may be disabled.
- **Domain & Subdomain Locking**: Restricts execution to authorized domains, IP addresses, or wildcards (`*.example.com`).
- **Remote Lock & Kill-Switch**: Remotely suspend or lock customer installations instantly from your private license server. Remote locks take effect upon the next heartbeat check.
- **Offline Grace Window**: Configurable tolerance period (default: 7 days) ensures client websites remain fully operational during temporary network or license server outages.
- **Performance Optimized**: Sub-millisecond memoized request verification (0.009ms) and throttled disk writes eliminate database queries and disk bottlenecks during normal page rendering.
- **Clock Rollback & Tamper Detection**: Detects manual manipulation of the server clock to bypass expiration dates, automatically restricting access and dispatching telemetry reports.
- **Professional Restriction Page**: Modern, responsive Tailwind-styled lockout page when an installation is unlicensed, expired, or locked.
- **Encrypted Local Storage**: The local certificate and remote status cache are stored encrypted using AES-256 with HMAC-SHA256 integrity verification.

---

## 2. Requirements

- **PHP**: 8.2 or higher
- **Extensions**: `ext-sodium` (recommended) or `paragonie/sodium_compat` (included as fallback), `ext-curl`, `ext-openssl`, `ext-json`
- **Framework**: Laravel 11.x or Laravel 12.x
- **Central Licensing Server**: CodeLock Central Authority (compatible with Laravel 12)

---

## 3. Installation

Install the package via Composer into your Laravel application:

```bash
composer require rasel673/codelock
```

After installation, run the automated installer command to publish the configuration and view assets:

```bash
php artisan codelock:install
```

This will publish:
- `config/codelock.php`
- `resources/views/vendor/codelock/locked.blade.php`

---

## 4. Configuration Reference

Set up your licensing environment variables in `.env`:

```dotenv
# Master switch (true to enforce licensing, false to bypass during development)
CODELOCK_ENABLED=true

# Product identifier configured on your central license server
CODELOCK_PRODUCT_ID=PROD-YOUR-PRODUCT-CODE

# Private licensing server URL
CODELOCK_SERVER_URL=https://license.yourdomain.com

# Customer's license key (can also be entered via artisan command)
CODELOCK_LICENSE_KEY=CLK-XXXX-XXXX-XXXX-XXXX

# Ed25519 Public Key (32-byte Base64 string from your license server)
CODELOCK_PUBLIC_KEY=your_base64_encoded_ed25519_public_key_here

# Optional Key ID for key rotation environments
CODELOCK_KEY_ID=key_default

# Heartbeat & Automatic Synchronization Policy
CODELOCK_HEARTBEAT_ENABLED=true
CODELOCK_AUTOMATIC_SYNC=true
CODELOCK_HEARTBEAT_INTERVAL=6
CODELOCK_HEARTBEAT_INTERVAL_MINUTES=5
CODELOCK_HEARTBEAT_CONNECT_TIMEOUT=3
CODELOCK_HEARTBEAT_REQUEST_TIMEOUT=5

# Offline Grace Period (Days)
CODELOCK_OFFLINE_GRACE_PERIOD=7

# Global Middleware Enforcement (true to guard all web and API routes automatically)
CODELOCK_GLOBAL_MIDDLEWARE=true

# Support contact information shown on the lock screen
CODELOCK_CONTACT_EMAIL=support@yourdomain.com
CODELOCK_CONTACT_URL=https://yourdomain.com/support

# Local development bypass (keep false in production)
CODELOCK_ALLOW_LOCAL=false
```

### Full Configuration Settings

| Setting | Env Variable | Default | Description |
| :--- | :--- | :---: | :--- |
| `enabled` | `CODELOCK_ENABLED` | `true` | Master toggle for license enforcement. |
| `product_id` | `CODELOCK_PRODUCT_ID` | `''` | Unique product identifier configured on your server. |
| `server_url` | `CODELOCK_SERVER_URL` | `''` | Base URL of central licensing authority. |
| `license_key` | `CODELOCK_LICENSE_KEY` | `''` | Assigned customer license key. |
| `public_key` | `CODELOCK_PUBLIC_KEY` | `''` | 32-byte Ed25519 Base64 public verification key. |
| `key_id` | `CODELOCK_KEY_ID` | `null` | Key ID for multi-key rotation setups. |
| `installation_id` | `CODELOCK_INSTALLATION_ID` | `null` | Explicit deployment UUID (auto-generated if omitted). |
| `heartbeat_enabled` | `CODELOCK_HEARTBEAT_ENABLED` | `true` | Enables periodic remote license check-ins. |
| `automatic_sync` | `CODELOCK_AUTOMATIC_SYNC` | `true` | Automatically triggers check-ins via web traffic (no-cron). |
| `heartbeat_interval` | `CODELOCK_HEARTBEAT_INTERVAL` | `6` | Heartbeat interval in hours. |
| `heartbeat_interval_minutes`| `CODELOCK_HEARTBEAT_INTERVAL_MINUTES`| `5` | High-frequency interval in minutes (takes precedence if set). |
| `heartbeat_connect_timeout`| `CODELOCK_HEARTBEAT_CONNECT_TIMEOUT`| `3` | Connection timeout in seconds. |
| `heartbeat_request_timeout`| `CODELOCK_HEARTBEAT_REQUEST_TIMEOUT`| `5` | Request timeout in seconds. |
| `offline_grace_period` | `CODELOCK_OFFLINE_GRACE_PERIOD` | `7` | Maximum operating days during server outages. |
| `auto_register_middleware` | `CODELOCK_GLOBAL_MIDDLEWARE` | `true` | Automatically injects `EnsureLicensed` globally. |
| `allow_local` | `CODELOCK_ALLOW_LOCAL` | `false` | Bypasses checks for localhost and 127.0.0.1 (dev only). |

---

## 5. License Activation

To activate a customer's license on a target server:

```bash
php artisan codelock:activate CLK-XXXX-XXXX-XXXX-XXXX
```

CodeLock connects to your licensing server, authenticates the key, verifies authorized domains, gathers the hardware fingerprint, downloads the Ed25519-signed license certificate, and encrypts it locally into `storage/app/.codelock.lic`.

---

## 6. Automatic Heartbeat Without Cron (No-Cron Architecture)

### The Problem in Traditional Licensing
Traditional packages force customer developers or non-technical site owners to manually set up cPanel cron jobs (`* * * * * php artisan schedule:run`). In reality, customers frequently fail or forget to configure crons, causing licenses to unexpectedly expire or desynchronize.

### The CodeLock Solution
CodeLock **automatically triggers synchronization when customer website requests arrive**:

```
[ Visitor Request ]
        │
        ▼
[ EnsureLicensed Middleware: Fast Verification (<1ms) ]
        │
        ▼
[ Response Sent to Visitor ] ──> Visitor experiences zero delay
        │
        ▼ (Post-Response Lifecycle: fastcgi_finish_request / terminate)
[ Check Sync Due? (e.g. >= 5 mins elapsed) ]
        │
        ├─► [ Acquire Non-Blocking Atomic Lock ]
        │         │
        │         ├─► [ Lock busy? Skip cleanly ]
        │         │
        │         └─► [ Send Heartbeat to Server (3s connect, 5s timeout) ]
        │                   │
        │                   └─► [ Verify Ed25519 Response & Update Sync Time ]
        │
        └─► [ Release Lock ]
```

### Key Technical Guarantees:
1. **Zero Visitor Latency**: In PHP-FPM / FastCGI environments, `fastcgi_finish_request()` flushes the response and closes the HTTP connection to the browser before the heartbeat network request begins.
2. **Post-Response Execution**: Utilizes Laravel's terminable middleware (`terminate()`), ensuring ordinary page rendering is never blocked waiting for licensing server responses.
3. **Stampede / Concurrency Protection**: Uses an atomic file lock (`.codelock.sync.lock`) with non-blocking mode (`LOCK_NB`). If multiple visitors arrive at the exact second a check-in is due, only **one** request executes the sync; all other requests skip it immediately.
4. **Short Timeouts**: Strict 3-second connection and 5-second request timeouts prevent hanging even in environments without FastCGI.

### Important Hosting Limitation
> [!IMPORTANT]
> **Idle Installations:**  
> Automatic no-cron synchronization requires incoming web traffic. A completely dormant website with zero visitors will not execute PHP code and therefore cannot synchronize until traffic arrives.
> 
> For mission-critical background workers or internal API servers with zero public HTTP traffic, you may optionally configure Laravel's scheduler:
> ```bash
> * * * * * cd /path-to-app && php artisan schedule:run >> /dev/null 2>&1
> ```
> CodeLock automatically registers `codelock:heartbeat` in Laravel's Task Scheduler so both traffic-triggered and cron-triggered execution work together harmoniously without collision.

---

## 7. Performance & Optimization

CodeLock is architected from the ground up to introduce negligible overhead to your application:

1. **In-Memory Request Memoization**:
   The verification result is cached per request (`_codelock_result`). Multiple calls to `LicenseManager::check()`, `can()`, or middleware within the same HTTP request execute in **0.0089 milliseconds**.
2. **Throttled Disk Writes**:
   Monotonic clock verification timestamps (`.codelock.time`) are throttled to write only once every 60 seconds. Lock states (`.codelock.lock_state`) only write when status changes. This reduces filesystem writes by over **99%**, dropping unmemoized verification latency from 30ms to under 1ms.
3. **No Database Queries**:
   License verification operates entirely from atomic encrypted storage files outside the public web root (`storage/app/`), avoiding any database locks, table joins, or SQL overhead.

---

## 8. Global Middleware & Route Protection

### Automatic Global Enforcement (Default)
When installed, CodeLock automatically registers `EnsureLicensed` as a global HTTP middleware in Laravel's HTTP Kernel. All incoming web and API traffic is automatically guarded.

- **Route Exclusions**: Health probes and internal endpoints (`/up`, `/health`, `/healthz`, `/codelock/*`) bypass license verification automatically.
- **REST API Responses**: Unlicensed or locked API requests receive structured JSON with HTTP 403 or 423:
  ```json
  {
      "error": "license_restriction",
      "code": "E_LICENSE_RESTRICTION",
      "status": "LOCKED",
      "message": "This installation has been locked remotely.",
      "customer_reference": "REF-A1B2C3D4-567890AB",
      "domain": "customer-domain.com"
  }
  ```
- **Web Browser Responses**: Browser requests receive an inline, responsive lockout view with commercial support contact details.

### Manual Route Protection (Optional)
To manually assign middleware to specific route groups, set `CODELOCK_GLOBAL_MIDDLEWARE=false` in `.env` and use the registered alias:

```php
Route::middleware(['web', 'codelock'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
```

---

## 9. Artisan CLI Commands

| Command | Description |
| :--- | :--- |
| `php artisan codelock:install` | Publishes config, views, inspects environment, and verifies cryptographic drivers. |
| `php artisan codelock:activate [key] [--domain=]` | Activates a commercial license key for the target domain. |
| `php artisan codelock:heartbeat [--force]` | Manually sends an authenticated check-in, verifies the signed server response, and synchronizes status. |
| `php artisan codelock:status [--domain=]` | Displays a detailed CLI status table showing health, product code, expiry, and sync metrics. |
| `php artisan codelock:check [--silent]` | Verifies license and returns exit code `0` (valid) or `1` (invalid) for CI/CD or automation. |
| `php artisan codelock:refresh` | Forces an immediate status refresh and synchronizes remote lock orders with the server. |
| `php artisan codelock:deactivate [--force]` | Releases the license on the remote server and wipes local certificates. |
| `php artisan codelock:integrity-manifest --key=` | Generates and signs an integrity manifest over package files for distribution. |

---

## 10. Offline Grace Period & Server Outages

If your licensing server undergoes maintenance or experiences a network outage:
- CodeLock automatically enters **Offline Grace Mode**.
- The customer application continues running normally without interruption during the configured grace window (`CODELOCK_OFFLINE_GRACE_PERIOD`, default: 7 days).
- Outbound network failures are logged as warnings and never crash or interrupt customer page visits.
- If the server remains unreachable after the grace window lapses, the application transitions to restricted mode with `E_GRACE_EXCEEDED` until connectivity is restored.

---

## 11. Cryptographic Package Integrity Monitoring

CodeLock features a built-in cryptographic file integrity monitor (`Rasel\CodeLock\IntegrityMonitor`) that protects core enforcement classes against accidental corruption or unauthorized modification:

1. **Signed Integrity Manifest**: Protected files are hashed with SHA-256 and signed with an Ed25519 private key into `resources/integrity.json`.
2. **LF Normalization**: File linebreaks are standardized (`\r\n` $\rightarrow$ `\n`) before hashing, preventing false alarms across Windows, Linux, Git checkouts, or cPanel file uploads.
3. **Cached Verification**: Clean verification states are cached for 1 hour (`CODELOCK_INTEGRITY_CACHE_TTL=3600`), supplemented by a 5% stochastic check on web requests to eliminate filesystem scanning bottlenecks.
4. **Tamper Telemetry**: If a protected file is altered or missing, CodeLock blocks execution and dispatches an untrusted telemetry incident report to your licensing server.

---

## 12. Security Architecture & Threat Model

- **Asymmetric Ed25519 Cryptography**: Signed envelopes use native PHP sodium (`sodium_crypto_sign_verify_detached`). Private keys **never** exist on client installations.
- **Deterministic RFC 8785 JSON**: Payloads are sorted canonically before hashing and verification, preventing JSON key reordering attacks.
- **Replay Protection**: Nonces and monotonic timestamps prevent attackers from replaying older active license envelopes to bypass expired or revoked states.
- **Sensitive Data Redaction**: Database credentials, passwords, auth tokens, session cookies, and credit cards are strictly redacted before dispatching telemetry. License keys are masked (`CLK-****-**-***-TEST`) in command outputs and logs.
- **No Hidden Backdoors**: CodeLock contains no master bypass keys or hardcoded backdoors. All recovery and activation paths require verifiable cryptographic signatures.

> [!WARNING]
> **Plain PHP Security Boundary:**  
> In user-space PHP, any code running on an untrusted server without bytecode encryption is ultimately readable by the server owner. CodeLock provides strong tamper detection, but cannot prevent bytecode patching by a skilled attacker with root access. For maximum copy protection, distribute your application compiled with PHP bytecode encoders (such as IonCube or SourceGuardian).

---

## 13. Running Automated Tests

Run the complete test suite using PHPUnit:

```bash
composer test
```

Or directly via PHPUnit:

```bash
./vendor/bin/phpunit
```

All 145 tests covering manual execution, automatic request-driven heartbeat, concurrency locks, signature verification, and domain matching run with zero errors.

---

## 14. License

Proprietary commercial software. All rights reserved.
