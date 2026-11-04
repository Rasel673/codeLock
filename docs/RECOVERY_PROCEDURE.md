# CodeLock: Application Recovery & Unlock Procedure

This guide documents the procedures for restoring application access when a protected application enters a restricted or locked state.

---

## 1. Understanding Restriction States

When CodeLock detects an issue, it halts protected routes and returns either an HTTP 403 (Forbidden) or HTTP 423 (Locked) response:

| Error Code | HTTP Status | Cause | Restoration Action |
| :--- | :---: | :--- | :--- |
| `E_STATUS_LOCKED` | **423** | Administrator initiated remote kill switch order | Vendor must unlock license on server; customer triggers recovery |
| `E_STATUS_SUSPENDED` | **403** | Subscription suspended for overdue invoice | Customer settles balance; vendor unlocks license |
| `E_GRACE_EXCEEDED` | **403** | Server failed to check in within 7-day grace period | Restore internet connectivity; run `codelock:refresh` |
| `E_TEMPORAL_EXPIRED` | **403** | Subscription date reached `expires_at` | Vendor extends license date; client syncs renewal |
| `E_INTEGRITY_MISMATCH` | **403** | Core package files modified or corrupted | Restore original package files via Composer |

---

## 2. Recovery Methods

### Method 1: Self-Service Browser Recovery (One-Click)
When the application is locked, visiting any protected web route displays the **Software License Restricted** screen:

1. After the vendor has lifted the remote restriction on the central server, open your application in any browser: `https://clientapp.com/dashboard`.
2. Locate the **Verify & Restore Access** button.
3. Click the button.
   - The browser sends a secure `POST` request to `/codelock/recover` with CSRF validation.
   - The application immediately performs an outbound handshake with the licensing server.
   - Upon receiving the signed `ACTIVE` status, the local lock state is cleared.
   - The browser automatically redirects back to your dashboard with full access restored.

> [!NOTE]
> The recovery endpoint enforces an IP-based rate limiter (maximum 3 attempts per minute). If repeatedly triggered while still locked, it will return HTTP 429 Too Many Attempts.

---

### Method 2: Command Line Recovery (CLI)
If you have SSH or terminal access to the customer server:
```bash
cd /home/customeruser/public_html
php artisan codelock:refresh
```

This commands forces an immediate heartbeat check-in with the central server, bypassing local cached state.

Confirm recovery:
```bash
php artisan codelock:status
```
*Expected Status:* `ACTIVE`.

---

### Method 3: Recovering from Package Integrity Violations (`E_INTEGRITY_MISMATCH`)
If an unauthorized modification was made to files in `vendor/rasel/codelock-laravel/`:
1. Reinstall the clean package files from the private repository:
   ```bash
   composer reinstall rasel/codelock-laravel
   ```
2. Clear internal caches:
   ```bash
   php artisan cache:clear
   php artisan view:clear
   ```
3. Test integrity:
   ```bash
   php artisan codelock:check
   ```

---

## 3. Emergency Vendor Override Token

If an isolated customer server experiences a complete network outage during an emergency lock remediation:
1. Vendor generates a signed emergency status document from the license server CLI:
   ```bash
   php artisan codelock:sign-status --license=CLK-XXXX-XXXX --status=ACTIVE --duration=72h
   ```
2. Vendor transmits the signed JSON payload to the customer administrator.
3. Customer administrator places the payload into:
   ```text
   storage/app/.codelock.status
   ```
4. The client application cryptographically verifies the vendor's signature and immediately grants temporary access for the specified duration.

