<?php

namespace Rasel\CodeLock\Enums;

enum LicenseStatus: string
{
    case ACTIVE = 'ACTIVE';
    case EXPIRED = 'EXPIRED';
    case SUSPENDED = 'SUSPENDED';
    case LOCKED = 'LOCKED';
    case REVOKED = 'REVOKED';
    case UNLICENSED = 'UNLICENSED';
    case INVALID = 'INVALID';
    case GRACE_PERIOD = 'GRACE_PERIOD';

    /**
     * Determine if this status allows application execution.
     */
    public function isUsable(): bool
    {
        return match ($this) {
            self::ACTIVE, self::GRACE_PERIOD => true,
            default => false,
        };
    }

    /**
     * Get human-readable description for UI / CLI presentation.
     */
    public function label(): string
    {
        return match ($this) {
            self::ACTIVE => 'Active & Valid',
            self::EXPIRED => 'Subscription Expired',
            self::SUSPENDED => 'Subscription Suspended',
            self::LOCKED => 'Remotely Locked',
            self::REVOKED => 'License Revoked',
            self::UNLICENSED => 'No License Installed',
            self::INVALID => 'Invalid Signature or Corrupted',
            self::GRACE_PERIOD => 'Active (Offline Grace Period)',
        };
    }
}

