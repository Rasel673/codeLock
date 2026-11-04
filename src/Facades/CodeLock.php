<?php

namespace Rasel\CodeLock\Facades;

use Illuminate\Support\Facades\Facade;
use Rasel\CodeLock\LicenseDocument;
use Rasel\CodeLock\LicenseManager;
use Rasel\CodeLock\LicenseVerificationResult;

/**
 * @method static bool isEnabled()
 * @method static LicenseVerificationResult verify(?string $domain = null, bool $throw = false)
 * @method static bool check(?string $domain = null)
 * @method static ?LicenseDocument getDocument(?string $domain = null)
 * @method static bool can(string $ability)
 * @method static bool hasFeature(string $feature)
 * @method static mixed quota(string $key, mixed $default = null)
 * @method static ?string tier()
 * @method static array entitlements()
 * @method static \Rasel\CodeLock\IntegrityResult checkIntegrity(bool $force = false)
 * @method static array activate(string $licenseKey, ?string $domain = null)
 * @method static array heartbeat()
 * @method static array refresh()
 * @method static bool deactivate(?string $domain = null)
 * @method static array status(?string $domain = null)
 * @method static \Illuminate\Http\Response renderLockResponse(?string $reason = null, int $statusCode = 403)
 * @method static ?string getLicenseKey()
 * @method static ?array getCertificate()
 *
 * @see \Rasel\CodeLock\LicenseManager
 */
class CodeLock extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return LicenseManager::class;
    }
}
