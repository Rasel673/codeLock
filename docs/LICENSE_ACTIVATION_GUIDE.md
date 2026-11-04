# CodeLock: License Activation Guide & Troubleshooting

This document explains the activation workflows available in **CodeLock** and provides troubleshooting steps for common activation errors.

---

## 1. Activation Methods

### Method 1: Artisan CLI Command (Recommended for Developers & Sysadmins)
From the root directory of your Laravel application:
```bash
php artisan codelock:activate CLK-XXXX-XXXX-XXXX-XXXX
```

To explicitly bind to a specific authorized domain (e.g. in multi-tenant or CLI environments):
```bash
php artisan codelock:activate CLK-XXXX-XXXX-XXXX-XXXX --domain=crm.yourdomain.com
```

---

### Method 2: In-App Web Wizard (For End-Users Without Shell Access)
If your application provides an onboarding or setup wizard for non-technical clients, activate programmatically:

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Rasel\CodeLock\Facades\CodeLock;
use Rasel\CodeLock\Exceptions\CodeLockException;

class ActivationWizardController extends Controller
{
    public function activate(Request $request)
    {
        $request->validate([
            'license_key' => 'required|string|min:16',
        ]);

        try {
            $result = CodeLock::activate($request->input('license_key'));

            return redirect()->route('dashboard')->with(
                'success', 
                'Software license successfully verified and activated!'
            );
        } catch (CodeLockException $e) {
            return back()->withErrors([
                'license_key' => $e->getMessage()
            ]);
        }
    }
}
```

---

### Method 3: Headless / Docker Container Automated Activation
In containerized environments (Docker, Kubernetes) or automated provisioning scripts:
```bash
#!/usr/bin/env bash
if [ -n "$CODELOCK_LICENSE_KEY" ]; then
    php artisan codelock:activate "$CODELOCK_LICENSE_KEY" --no-interaction
fi
```

---

## 2. Troubleshooting Activation Errors

### Error: `E_DOMAIN_UNAUTHORIZED` (HTTP 422 / 403)
- **Symptom:** `Domain 'clientapp.com' is not authorized for this license.`
- **Cause:** The domain from which the request originated does not match the domains whitelisted on the license authority.
- **Resolution:**
  1. Verify the domain in `APP_URL` (`.env`) matches your browser URL.
  2. Contact your software vendor to add your domain to the license record.
  3. If behind a reverse proxy (Cloudflare, AWS ALB), ensure trusted proxies are configured in `bootstrap/app.php` so `$request->getHost()` reports your actual domain rather than the proxy hostname.

---

### Error: `E_ACTIVATIONS_EXCEEDED` (HTTP 422)
- **Symptom:** `License activation limit reached (max 1 seat).`
- **Cause:** The license key is already actively deployed on another server installation.
- **Resolution:**
  1. If moving servers: On the **old server**, execute deactivation:
     ```bash
     php artisan codelock:deactivate
     ```
  2. If the old server is inaccessible: Request that your vendor release the stale installation session from the server admin dashboard.

---

### Error: `E_KEY_UNKNOWN` or `E_SIGNATURE_MISMATCH`
- **Symptom:** `Cryptographic signature does not match payload.`
- **Cause:** The `CODELOCK_PUBLIC_KEY` in `.env` does not match the private signing key used by the license authority server.
- **Resolution:**
  1. Retrieve the vendor's active public key from `https://license.yourdomain.com/api/v1/public-key`.
  2. Ensure `.env` contains the exact Base64 public key string without trailing spaces or newline characters:
     ```dotenv
     CODELOCK_PUBLIC_KEY="YOUR_BASE64_PUBLIC_KEY"
     ```

---

### Error: `ServerCommunicationException` / Connection Refused
- **Symptom:** `Unable to connect to license server at [https://license.yourdomain.com].`
- **Cause:** Outbound network restriction or firewall blocking outbound HTTPS port 443.
- **Resolution:**
  1. Test outbound connectivity from your server terminal:
     ```bash
     curl -Iv https://license.yourdomain.com/api/v1/public-key
     ```
  2. If running on shared cPanel hosting: Contact hosting support to ensure outbound HTTPS calls via cURL are not blocked by host firewall rules (e.g. ConfigServer Security & Firewall - CSF).

