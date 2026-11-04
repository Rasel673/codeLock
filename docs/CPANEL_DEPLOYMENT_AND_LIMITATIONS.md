# cPanel Hosting: Deployment Best Practices & Environmental Limitations

This document addresses the technical nuances, hosting constraints, and configuration requirements for running CodeLock-protected Laravel applications in cPanel shared hosting and managed VPS environments.

---

## 1. Important Notice Regarding cPanel Hosting Diversity

> [!WARNING]
> **No Uniform cPanel Configuration Exists:**  
> cPanel is a management control panel, not an operating system. Every web hosting provider (e.g. cPanel with EasyApache 4, CloudLinux with CageFS, or LiteSpeed Web Server) configures PHP extensions, CLI binaries, memory caps, and process execution limits differently.
>
> **Do not assume that every cPanel hosting environment supports identical PHP extensions or identical CLI paths.**

---

## 2. Technical Limitations & Solutions

### 2.1 The `ext-sodium` Extension Requirement
CodeLock relies on PHP's native `ext-sodium` extension for Ed25519 digital signature verification.
- While `ext-sodium` has been part of PHP core since PHP 7.2, certain budget shared hosting providers compile custom PHP builds with `--without-sodium` or disable it in default `php.ini` profiles.
- **Verification Command (cPanel Terminal):**
  ```bash
  /usr/local/bin/ea-php82 -m | grep -i sodium
  ```
  *(Or check your cPanel `phpinfo()` screen).*
- **Resolution if Missing:**
  - **CloudLinux Hosts:** In cPanel, navigate to **Select PHP Version** $\rightarrow$ **Extensions** $\rightarrow$ check `sodium`.
  - **EasyApache 4 Hosts:** Open a hosting support ticket requesting: *"Please enable the PHP 8.2 sodium extension (ea-php82-php-sodium) for my account."*

---

### 2.2 PHP CLI vs. Web Runtime Version Mismatch
A frequent pitfall in cPanel is running `php artisan` and invoking a legacy system PHP binary:
- The cPanel web domain may be running **PHP 8.2**, while `/usr/bin/php` in terminal points to **PHP 7.4** or **PHP 8.0**.
- Running `php artisan codelock:activate` with an older binary will fail with syntax or version mismatch errors.
- **Resolution:**
  Always use the explicit, absolute path to your active cPanel PHP version:
  - **EasyApache 4:** `/usr/local/bin/ea-php82`
  - **CloudLinux Alt-PHP:** `/usr/local/bin/alt-php82`

**Example:**
```bash
/usr/local/bin/ea-php82 artisan codelock:activate CLK-XXXX-XXXX-XXXX-XXXX
```

---

### 2.3 Disabled Process Functions (`disable_functions`)
Many shared cPanel hosts disable shell execution functions in `php.ini`:
```text
disable_functions = exec, passthru, shell_exec, system, proc_open, popen
```
- **CodeLock Compatibility:**
  CodeLock is engineered to operate cleanly on locked-down hosts. It **never invokes `exec()` or `proc_open()`** for cryptographic verification or network communication. It uses in-memory libsodium functions and Guzzle/cURL streams directly.

---

### 2.4 Document Root Alignment (`public_html` vs. `public`)
Laravel requires the web server document root to point to the `public/` directory, while cPanel defaults to `/home/username/public_html/`.

**Recommended Layout (Two Directory Approach):**
1. Place the Laravel application in a non-public folder: `/home/username/app/`.
2. Delete the default `public_html` directory:
   ```bash
   rm -rf /home/username/public_html
   ```
3. Create a symbolic link from Laravel's `public` directory to `public_html`:
   ```bash
   ln -s /home/username/app/public /home/username/public_html
   ```
4. Verify web requests serve directly from `/home/username/app/public/index.php`.

> [!CAUTION]
> Avoid moving `index.php` directly into `public_html` while leaving the rest of the application exposed. This creates file path resolution errors and risks exposing your `.env` file containing application secrets to the public web.

---

### 2.5 Outbound Firewall & Port 443 Restrictions
Certain shared hosting providers deploy aggressive outbound firewall filtering (ConfigServer Security & Firewall - CSF):
- If the host blocks outbound TCP port 443 for customer accounts, the client package cannot communicate with `https://license.yourdomain.com`.
- **Test Command:**
  ```bash
  curl -Iv https://license.yourdomain.com/api/v1/public-key
  ```
- If the connection times out: Contact your hosting provider's support team to whitelist the licensing domain for outbound HTTPS requests.

---

### 2.6 cPanel Cron Task Setup for Heartbeat Sync
In cPanel **Cron Jobs**, set the schedule:

```text
Common Settings: Once Per Hour (or Once Per Day)
Minute: 0
Hour: 2
Day: *
Month: *
Weekday: *
```

Command:
```bash
cd /home/username/app && /usr/local/bin/ea-php82 artisan schedule:run >> /dev/null 2>&1
```

*CodeLock's internal heartbeat scheduler checks if a sync is due (configured to 24 hours by default), ensuring that running the cron once per hour creates minimal CPU overhead on shared hosting quotas.*

