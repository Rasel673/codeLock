<?php

namespace Rasel\CodeLock;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Rasel\CodeLock\Exceptions\LicenseInvalidException;
use Rasel\CodeLock\Exceptions\ServerCommunicationException;
use Rasel\CodeLock\Support\CanonicalJson;
use Rasel\CodeLock\Support\LicenseKey;
use Rasel\CodeLock\Support\MachineFingerprint;

class LicenseClient
{
    protected GuzzleClient $http;
    protected string $serverUrl;
    protected ?string $productId;
    protected int $timeout;

    public function __construct(
        ?string $serverUrl = null,
        ?string $productId = null,
        ?int $timeout = null,
        ?GuzzleClient $http = null
    ) {
        $this->serverUrl = rtrim($serverUrl ?? (string) config('codelock.server_url', config('codelock.license_server_url', '')), '/');
        $this->productId = $productId ?? config('codelock.product_id');
        $this->timeout = $timeout ?? (int) config('codelock.heartbeat_request_timeout', config('codelock.request_timeout', 5));
        $connectTimeout = (int) config('codelock.heartbeat_connect_timeout', 3);
        $this->http = $http ?? new GuzzleClient([
            'timeout' => $this->timeout,
            'connect_timeout' => $connectTimeout,
            'http_errors' => false,
        ]);
    }

    /**
     * Send activation request to the central license server.
     *
     * @param string $licenseKey
     * @param string $domain
     * @param array $extraMetadata
     * @return array Returned signed license certificate
     * @throws ServerCommunicationException|LicenseInvalidException
     */
    public function activate(string $licenseKey, string $domain, array $extraMetadata = []): array
    {
        // 1. Validate License Key Format Before Transmitting
        if (!LicenseKey::isValidFormat($licenseKey)) {
            throw new LicenseInvalidException(
                "Invalid license key format [{$licenseKey}]. License key must be an alphanumeric token (e.g. CLK-XXXX-XXXX-XXXX)."
            );
        }

        $cleanKey = LicenseKey::normalize($licenseKey);

        $payload = array_merge([
            'license_key' => $cleanKey,
            'instance_id' => MachineFingerprint::get(),
            'domain' => $domain,
            'app_url' => config('app.url', 'http://' . $domain),
            'environment' => app()->environment(),
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'package_version' => '1.0.0',
            'nonce' => bin2hex(random_bytes(16)),
            'timestamp' => time(),
        ], $extraMetadata);

        return $this->post('/api/v1/license/activate', $payload, $cleanKey);
    }

    /**
     * Send heartbeat to remote server to synchronize status and receive remote lock orders.
     */
    public function heartbeat(
        string $licenseKey,
        string $installationId,
        string $domain,
        ?string $installedHash = null,
        ?string $productId = null,
        ?string $packageVersion = null,
        mixed $integrityStatus = null,
        array $extra = []
    ): array {
        $cleanKey = LicenseKey::normalize($licenseKey);

        $payload = array_merge([
            'license_key' => $cleanKey,
            'license_id' => $cleanKey,
            'instance_id' => $installationId,
            'installation_id' => $installationId,
            'product_id' => $productId ?? $this->productId ?? (string) config('codelock.product_id', ''),
            'domain' => $domain,
            'authorized_domain' => $domain,
            'package_version' => $packageVersion ?? '1.0.0',
            'integrity_status' => $integrityStatus ?? 'VALID',
            'installed_hash' => $installedHash,
            'timestamp' => time(),
            'nonce' => bin2hex(random_bytes(16)),
        ], $extra);

        $customHeaders = [];
        if (!empty($extra['token'])) {
            $customHeaders['Authorization'] = 'Bearer ' . $extra['token'];
        }

        return $this->post('/api/v1/license/heartbeat', $payload, $cleanKey, $customHeaders);
    }

    /**
     * Deactivate this installation on the central server.
     */
    public function deactivate(string $licenseKey, string $installationId, string $domain, ?string $token = null): array
    {
        $cleanKey = LicenseKey::normalize($licenseKey);

        $payload = [
            'license_key' => $cleanKey,
            'instance_id' => $installationId,
            'installation_id' => $installationId,
            'domain' => $domain,
            'timestamp' => time(),
            'nonce' => bin2hex(random_bytes(16)),
        ];

        if ($token !== null) {
            $payload['token'] = $token;
        }

        $customHeaders = [];
        if ($token !== null) {
            $customHeaders['Authorization'] = 'Bearer ' . $token;
        }

        return $this->post('/api/v1/license/deactivate', $payload, $cleanKey, $customHeaders);
    }

    /**
     * Dispatch an anomalous security event report to the central server.
     */
    public function reportSecurityEvent(
        string $eventCode,
        string $severity,
        array $details,
        ?string $licenseKey = null,
        ?string $domain = null
    ): array {
        try {
            $key = $licenseKey ?? config('codelock.license_key');
            $cleanKey = !empty($key) ? LicenseKey::normalize($key) : 'UNSPECIFIED';

            $payload = [
                'license_key' => $cleanKey,
                'instance_id' => MachineFingerprint::get(),
                'domain' => $domain ?? 'unknown',
                'event_code' => $eventCode,
                'severity' => strtoupper($severity),
                'details' => $details,
                'timestamp' => time(),
            ];

            return $this->post('/api/v1/license/security-event', $payload, $cleanKey);
        } catch (\Throwable $e) {
            // Telemetry failure must never crash the client application
            return ['status' => 'failed_to_report', 'error' => $e->getMessage()];
        }
    }

    /**
     * Perform HTTP POST request with standardized headers, robust error translation, and key masking.
     */
    protected function post(string $endpoint, array $data, ?string $rawKey = null, array $customHeaders = []): array
    {
        $url = $this->serverUrl . $endpoint;
        $maskedKey = $rawKey ? LicenseKey::mask($rawKey) : 'N/A';

        $headers = array_merge([
            'User-Agent' => 'CodeLock-Client/1.0.0 (Laravel ' . app()->version() . ')',
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
        ], $customHeaders);

        if (!empty($this->productId)) {
            $headers['X-CodeLock-Product'] = $this->productId;
        }

        if (isset($data['timestamp'])) {
            $headers['X-CodeLock-Timestamp'] = (string) $data['timestamp'];
        }
        if (isset($data['nonce'])) {
            $headers['X-CodeLock-Nonce'] = (string) $data['nonce'];
        }
        if (!empty($data['instance_id']) || !empty($data['installation_id'])) {
            $headers['X-CodeLock-Instance'] = (string) ($data['instance_id'] ?? $data['installation_id']);
        }
        if ($rawKey) {
            $headers['X-CodeLock-Key'] = $maskedKey;
            $canonicalPayload = CanonicalJson::encode($data);
            $headers['X-CodeLock-Signature'] = hash_hmac('sha256', $canonicalPayload, $rawKey);
        }

        try {
            $response = $this->http->post($url, [
                'headers' => $headers,
                'json' => $data,
            ]);

            $statusCode = $response->getStatusCode();
            $body = (string) $response->getBody();
            $json = json_decode($body, true);

            // Handle invalid/non-JSON server responses
            if (!is_array($json)) {
                $truncatedBody = substr(strip_tags($body), 0, 150);
                throw new ServerCommunicationException(
                    "License server returned unreadable non-JSON response [HTTP {$statusCode}]: {$truncatedBody}",
                    ['status_code' => $statusCode, 'server_url' => $this->serverUrl, 'license_key' => $maskedKey]
                );
            }

            // Handle HTTP 4xx and 5xx responses
            if ($statusCode >= 400) {
                if ($statusCode === 423 && is_array($json) && (isset($json['payload']) || isset($json['signed_status']))) {
                    return $json;
                }

                $errorMsg = $json['message'] ?? $json['error'] ?? "License server responded with HTTP {$statusCode}";
                throw new ServerCommunicationException($errorMsg, [
                    'status_code' => $statusCode,
                    'server_url' => $this->serverUrl,
                    'license_key' => $maskedKey,
                    'response' => $json,
                ]);
            }

            return $json;
        } catch (ConnectException $e) {
            // DNS resolution failure, connection timeout, connection refused
            throw new ServerCommunicationException(
                "Unable to connect to license server at [{$this->serverUrl}]. Please verify network connectivity and server URL.",
                ['server_url' => $this->serverUrl, 'license_key' => $maskedKey],
                $e
            );
        } catch (RequestException $e) {
            if ($e->hasResponse()) {
                $response = $e->getResponse();
                $statusCode = $response->getStatusCode();
                $body = (string) $response->getBody();
                $json = json_decode($body, true);

                if (is_array($json) && $statusCode === 423 && (isset($json['payload']) || isset($json['signed_status']))) {
                    return $json;
                }

                if (!is_array($json)) {
                    $truncatedBody = substr(strip_tags($body), 0, 150);
                    throw new ServerCommunicationException(
                        "License server returned unreadable non-JSON response [HTTP {$statusCode}]: {$truncatedBody}",
                        ['status_code' => $statusCode, 'server_url' => $this->serverUrl, 'license_key' => $maskedKey],
                        $e
                    );
                }

                $errorMsg = $json['message'] ?? $json['error'] ?? "License server responded with HTTP {$statusCode}";
                throw new ServerCommunicationException($errorMsg, [
                    'status_code' => $statusCode,
                    'server_url' => $this->serverUrl,
                    'license_key' => $maskedKey,
                    'response' => $json,
                ], $e);
            }

            throw new ServerCommunicationException(
                "License server network communication failure: " . $e->getMessage(),
                ['server_url' => $this->serverUrl, 'license_key' => $maskedKey],
                $e
            );
        } catch (GuzzleException $e) {
            throw new ServerCommunicationException(
                "License server network communication failure: " . $e->getMessage(),
                ['server_url' => $this->serverUrl, 'license_key' => $maskedKey],
                $e
            );
        }
    }
}
