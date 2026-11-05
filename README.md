# CodeLock for Laravel (`rasel673/codelock`)

[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-11%20%7C%2012-red.svg)](https://laravel.com)
[![Cryptography](https://img.shields.io/badge/Security-Ed25519-green.svg)](https://ed25519.cr.yp.to/)
[![License](https://img.shields.io/badge/License-Proprietary-darkblue.svg)](#)

**CodeLock** is a high-security, commercial software licensing and anti-piracy package built specifically for the Laravel ecosystem. It protects commercial Laravel software applications, SaaS boilerplates, and self-hosted products distributed to end-customers.

---

## Key Capabilities

- **Ed25519 Cryptographic Signatures**: Hardware-accelerated signature verification ensures license certificates cannot be forged or tampered with even if customer source files are modified.
- **cPanel & Shared Hosting Hardened**: Features a dual-driver crypto engine (`ext-sodium` with automatic fallback to `paragonie/sodium_compat`), guaranteeing operation across restrictive cPanel environments where native extensions may be disabled.
- **Domain & Subdomain Locking**: Restricts execution to authorized domains, IP addresses, or wildcards (`*.example.com`).
- **Remote Lock & Kill-Switch**: Remotely lock customer installations instantly from your private license server. Remote locks take effect upon the next heartbeat check.
- **Offline Grace Window**: Configurable tolerance period (default: 7 days) ensures client websites remain fully operational during temporary network or license server outages.
- **Clock Rollback & Tamper Detection**: Detects manual manipulation of the server clock to bypass expiration dates, automatically locking the application and dispatching security reports.
- **Professional Restriction Page**: Modern, responsive Tailwind-styled lockout page when an installation is unlicensed, expired, or locked.
- **Encrypted Local Storage**: The local certificate and remote status cache are stored encrypted using AES-256 with HMAC-SHA256 integrity verification.

---

## Installation

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

## Configuration

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

# Heartbeat & Grace Policy
CODELOCK_OFFLINE_GRACE_PERIOD=7
CODELOCK_HEARTBEAT_INTERVAL=6

# Global Middleware Enforcement (true to guard all web and API routes automatically)
CODELOCK_GLOBAL_MIDDLEWARE=true

# Support contact information shown on the lock screen
CODELOCK_CONTACT_EMAIL=support@yourdomain.com
CODELOCK_CONTACT_URL=https://yourdomain.com/support

# Local development bypass (keep false in production)
CODELOCK_ALLOW_LOCAL=false
```

---

## Global Middleware & Route Protection

### Automatic Global Enforcement (Default)
When installed, CodeLock **automatically registers `EnsureLicensed` as a global HTTP middleware** across the application. All incoming HTTP traffic (web and API) is automatically verified against your license policies without requiring manual middleware additions.

- **Route Exclusions**: Health probes and internal endpoints (`/up`, `/health`, `/healthz`, `/codelock/*`) bypass license verification automatically via `config('codelock.excluded_paths')`.
- **Request Memoization**: The verification result is cached in memory per request (`_codelock_result`), guaranteeing zero redundant cryptographic operations during request lifecycle.

If you prefer to manually protect specific route groups rather than using global enforcement, disable automatic registration in `.env`:

```dotenv
CODELOCK_GLOBAL_MIDDLEWARE=false
```

### Manual Route Protection (Optional)
When global enforcement is disabled, use the registered `codelock` (or `codelock.verify`) middleware alias:

```php
use Illuminate\Support\Facades\Route;

// Protect a group of web routes (renders HTML lockout page on violation)
Route::middleware(['web', 'codelock'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
    Route::resource('invoices', InvoiceController::class);
});

// Protect API routes (returns HTTP 403 JSON with structured error code)
Route::middleware(['api', 'codelock'])->prefix('api/v1')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::post('/transactions', [TransactionController::class, 'store']);
});
```

---

## Artisan CLI Commands

CodeLock includes a complete suite of management commands:

| Command | Description |
| :--- | :--- |
| `php artisan codelock:install` | Publishes config, views, inspects environment, and outputs installation fingerprint. |
| `php artisan codelock:activate [key] [--domain=]` | Activates a commercial license key for the current domain. |
| `php artisan codelock:heartbeat [--force]` | Sends an authenticated check-in to the central license server, verifies the signed Ed25519 response, and synchronizes status. |
| `php artisan codelock:status [--domain=]` | Displays a comprehensive CLI status table showing health, product, and expiry. |
| `php artisan codelock:check [--silent]` | Verifies license and returns exit code `0` (valid) or `1` (invalid) for CI/CD or crons. |
| `php artisan codelock:refresh` | Forces a status refresh and synchronizes remote lock orders with the server. |
| `php artisan codelock:deactivate [--force]` | Releases the license on the remote server and wipes local certificates. |

---

## Automated Heartbeat Scheduler

CodeLock **automatically registers** the heartbeat synchronization command in Laravel's Task Scheduler through the package Service Provider.

### How It Operates:
- **Zero Configuration Required**: The scheduler automatically picks up `codelock:heartbeat` when the package is installed.
- **Configurable Interval**: Set `CODELOCK_HEARTBEAT_INTERVAL` in `.env` (defaults to `6` hours).
- **Concurrency & Overlap Protection**: Runs with `withoutOverlapping(60)` to prevent duplicate concurrent heartbeat tasks.
- **Smart Guards**: Automatically skips heartbeat check-ins when CodeLock is disabled or when no license certificate is installed.
- **Resilient Offline Grace**: If the licensing server is temporarily unreachable, the software seamlessly operates in offline grace period mode (default: 7 days) and does not noisily fail cron executions.

### Inspecting Scheduled Tasks
To inspect the scheduled heartbeat task in your Laravel application:

```bash
php artisan schedule:list
```

Output:
```
0 */6 * * *  php artisan codelock:heartbeat ... Next Due: X hours from now
```

### Production Cron Setup
To ensure Laravel executes scheduled tasks in production, add standard Laravel scheduler cron to your server's crontab:

```bash
* * * * * cd /path-to-your-application && php artisan schedule:run >> /dev/null 2>&1
```

---

## Architecture & Class Overview

```
src/
├── CodeLockServiceProvider.php   # Service provider, config merge, middleware & command registration
├── LicenseManager.php            # Primary service orchestrator (singleton)
├── LicenseVerifier.php           # Ed25519 signature, domain, clock, and policy verifier
├── LicenseClient.php             # Guzzle HTTP client communicating with license server
├── LicenseHeartbeat.php          # Periodic heartbeat check-ins, HMAC authentication & offline grace
├── SecurityEventReporter.php     # Sanitized, rate-limited, non-blocking security telemetry
├── RemoteLicenseStatus.php       # Typed, immutable, cryptographically signed remote status document
├── HeartbeatResult.php           # Structured heartbeat outcome with grace period metrics
├── IntegrityMonitor.php          # SHA-256 package file integrity monitoring & manifest verification
├── IntegrityResult.php           # Structured file integrity result
├── Facades/
│   └── CodeLock.php              # Laravel Facade
├── Http/
│   └── Middleware/
│       └── EnsureLicenseValid.php# HTTP request gatekeeper alias
├── Middleware/
│   └── EnsureLicensed.php        # Primary route middleware with lock screen & JSON responses
├── Commands/                     # Artisan CLI command suite
├── Enums/
│   ├── LicenseStatus.php         # ACTIVE, EXPIRED, SUSPENDED, LOCKED, etc.
│   └── SecurityEventCode.php     # DOMAIN_MISMATCH, TAMPER_DETECTED, INTEGRITY_MISMATCH, etc.
├── Exceptions/                   # Structured domain exceptions
├── Storage/
│   └── LicenseStorage.php        # Encrypted file persistence (AES-256-CBC)
└── Support/
    ├── CanonicalJson.php         # RFC 8785 deterministic JSON serializer
    ├── Ed25519Verifier.php       # Sodium / SodiumCompat crypto wrapper
    ├── LicenseKey.php            # Key format validation & safe masking
    └── MachineFingerprint.php    # Stable hardware/instance fingerprint
```

---

## Running Package Tests

Run the test suite using PHPUnit:

```bash
composer test
```
Or directly:
```bash
./vendor/bin/phpunit
```

---

## Cryptographic Integrity Monitoring

CodeLock features a built-in cryptographic integrity monitor (`Rasel\CodeLock\IntegrityMonitor`) that protects designated core package enforcement files against casual tampering, unauthorized bypass scripts, and file corruption.

### How It Works:
1. **Signed Integrity Manifest**: Designated enforcement files (`src/LicenseVerifier.php`, `src/LicenseManager.php`, `src/Middleware/EnsureLicensed.php`, etc.) are hashed using SHA-256 and signed with an Ed25519 private key into `resources/integrity.json`.
2. **LF Normalization**: File contents are normalized (`\r\n` $\rightarrow$ `\n`) before hashing, preventing false-positive integrity alarms across Windows, Linux, Git checkouts, or cPanel file uploads.
3. **Optimized Stochastic & Cached Execution**: To ensure zero performance degradation under budget cPanel I/O limits, clean integrity states are cached with a configurable TTL (default: 3600s), complemented by random tripwire checks on 5% of web requests.
4. **Immediate Tripwire Reporting**: If a protected file is altered or missing, CodeLock blocks execution and immediately transmits a `TAMPER_DETECTED` telemetry event to your central license server.

### Generating Manifests (Build / Release):
```bash
php artisan codelock:integrity-manifest --key=YOUR_ED25519_SECRET_KEY
```

---

## Heartbeat & Security Telemetry

CodeLock incorporates an enterprise-grade telemetry and remote lease management engine:

### 1. Periodic Heartbeat Check-ins (`LicenseHeartbeat`)
- **Payload Claims**: Automatically transmits installation fingerprint, product ID, license key, normalized authorized domain, package version, integrity status, and microsecond timestamps.
- **HMAC Request Authentication**: Every outbound request calculates an `X-CodeLock-Signature` HMAC-SHA256 header over canonical payload bytes using the customer's license key, preventing third-party request spoofing or tampering in transit.
- **Configurable Cadence**: Controlled via `CODELOCK_HEARTBEAT_INTERVAL` (default: 24 hours). Skips redundant network check-ins until due, or runs on-demand via `--force`.
- **Signed Remote Deadlines**: Server returns an Ed25519-signed `RemoteLicenseStatus` containing a monotonic `deadline`. If a server orders a remote lock, the lock executes upon the next check-in.
- **Offline Grace Protection**: If the license server experiences hosting downtime, DNS issues, or corporate firewall throttling, CodeLock guarantees uninterrupted customer operation during the offline grace window (`CODELOCK_OFFLINE_GRACE_PERIOD`, default: 7 days).

### 2. Sanitized Security Reporting (`SecurityEventReporter`)
- **Monitored Anomalies**: Detects and reports `INTEGRITY_MISMATCH`, `MISSING_PROTECTED_FILE`, `INVALID_SIGNATURE`, `DOMAIN_MISMATCH`, `SUSPICIOUS_CONFIG`, and `REPEATED_VERIFICATION_FAILURES`.
- **Zero-Data-Leak Guarantees**:
  - Customer database records, SQL queries, passwords, auth tokens, cookies, and credit cards are strictly redacted using regex filtering.
  - License keys are masked (`CLK-2026-****-****-BETA`) in logs and network traces.
- **Client-Side Rate Limiting**: Caps event dispatches per hour to protect against runaway error loops.
- **Untrusted Telemetry Contract**: Client security reports are categorized as untrusted evidence on the licensing server; CodeLock never permits a client request to automatically revoke or lock arbitrary licenses.

---

## Remote Lock, Kill Switch & Recovery Architecture

CodeLock incorporates a cryptographically verified remote kill switch and self-service recovery system:

### 1. State Enforcement & Responses
* **`ACTIVE`** (`200 OK`): Software is fully functional.
* **`SUSPENDED`** (`403 Forbidden` / Web Amber View): Temporary billing hold; displays invoice payment button (`action_url`).
* **`LOCKED`** (`423 Locked` / Web Crimson View): Security or compliance lock; displays instance identity and support link.
* **`REVOKED`** (`403 Forbidden` / Web Charcoal View): Permanent contract termination; files remain locked.
* **`E_GRACE_EXCEEDED`** (`403 Forbidden` / Web Slate View): Offline grace elapsed; server connection required.

### 2. Zero-SSH Self-Service Recovery (`POST /codelock/recover`)
* Locked users can click **"Verify & Restore Access"** directly on the lockout screen.
* The recovery endpoint is rate-limited (3 req/min/IP) and executes an authenticated heartbeat check-in.
* When the vendor server returns a signed `ACTIVE` status, application access is restored immediately without server restarts or SSH commands.

### 3. Zero-Redirect Protection
* CodeLock renders lockout views inline on protected routes with HTTP 403 / 423 rather than issuing HTTP 302 redirects. This completely prevents redirect loops between protected application routes and lockout views.

---

## Remote Lock Security Invariants & Limitations

> [!WARNING]
> **Understanding Remote Lock Realities in Distributed Environments:**
> 
> 1. **Client-Pull Latency (The Heartbeat Window):**
>    In self-hosted environments (cPanel, private VPS, behind NAT firewalls), the license server cannot push commands inward. Remote locks take effect upon the customer’s next automated heartbeat check-in (default 24h) or when an administrator clicks "Verify & Restore Access". To narrow this window, configure a shorter heartbeat interval (e.g. 6–12 hours).
> 
> 2. **Network Blackholing Is Strictly Bounded:**
>    If a customer attempts to evade a remote lock by blocking outbound traffic to your license server or modifying `/etc/hosts`, the software continues running only until the monotonic `deadline` lapses (default 7 days). Once the offline grace period expires, CodeLock locks automatically with `E_GRACE_EXCEEDED`.
> 
> 3. **Cryptographic Proof Required for Unlocking:**
>    CodeLock will **NEVER** unlock an installation based on local file editing or unsigned database changes. The client verifies the Ed25519 signature of the server on every status read. Unlocking strictly requires a cryptographically signed `ACTIVE` envelope from the vendor's private key.
> 
> 4. **User-Space PHP Boundary:**
>    As with all plain-text PHP software, a user with root or cPanel access can modify PHP files directly. CodeLock's `IntegrityMonitor` detects and reports modifications, but absolute execution immutability requires pairing CodeLock with compiled PHP bytecode encryption (IonCube or SourceGuardian).

---

## Security Invariants & Limitations

> [!WARNING]
> **Understanding the Security Boundary in Plain PHP:**
> 
> In an interpreted language like PHP, any code running in user-space without binary compilation or bytecode encryption is ultimately readable and editable by whoever controls the server filesystem (e.g. root or cPanel account owners).
> 
> **What CodeLock Integrity Monitoring Provides:**
> - **Tamper-Evident Tripwires:** Automatically detects 95%+ of casual infringers who attempt to modify license verification booleans or comment out middleware.
> - **Automated Telemetry:** Dispatches security alert notifications to your server the moment a client installation experiences file tampering.
> - **Accidental Corruption Prevention:** Identifies broken deployments, missing files, or incomplete git pulls.
> 
> **What User-Space PHP Cannot Prevent:**
> - CodeLock **does not claim impossible 100% tamper prevention** against a skilled developer who modifies the integrity checker itself or strips the package loader from `composer.json`.
> - **Server Policy Rule:** The licensing server treats client tamper reports as investigative security alerts and audit events; it never automatically revokes a paying customer's license solely from an unverified client report.
> - For absolute execution immutability, distribute your commercial application alongside commercial PHP bytecode encryption (such as IonCube or SourceGuardian) or a compiled C extension.
