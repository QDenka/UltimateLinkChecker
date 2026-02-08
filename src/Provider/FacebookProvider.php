<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Qdenka\UltimateLinkChecker\Contract\AbstractProvider;
use Qdenka\UltimateLinkChecker\Exception\ProviderException;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use Qdenka\UltimateLinkChecker\Result\Threat;

/**
 * Facebook URL Security provider.
 *
 * Uses the Facebook Graph API to check URL sharing safety.
 * Requires a valid Facebook App access token (app_id|app_secret).
 */
final class FacebookProvider extends AbstractProvider
{
    private const API_URL = 'https://graph.facebook.com/v18.0/';

    public function __construct(
        string $apiKey,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        float $timeout = 5.0,
        int $retries = 1
    ) {
        parent::__construct(
            $apiKey,
            $httpClient ?? new Client(['timeout' => $timeout]),
            $requestFactory ?? new HttpFactory(),
            $streamFactory ?? new HttpFactory(),
            $timeout,
            $retries
        );
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'facebook';
    }

    /**
     * @param string $url
     * @return CheckResult
     * @throws ProviderException
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            return $this->executeWithRetry(function () use ($normalizedUrl, $result): CheckResult {
                $queryParams = http_build_query([
                    'access_token' => $this->apiKey,
                    'scrape' => 'true',
                    'id' => $normalizedUrl,
                ]);

                $request = $this->requestFactory->createRequest('POST', self::API_URL . '?' . $queryParams)
                    ->withHeader('Content-Type', 'application/x-www-form-urlencoded');

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                // Facebook flags unsafe URLs in the 'og_object' or via error responses
                if (isset($data['error'])) {
                    $errorMessage = $data['error']['message'] ?? 'Unknown error';

                    // Error code 1 with specific messages indicates blocked/unsafe URL
                    if ($this->isSecurityError($data['error'])) {
                        $threat = new Threat(
                            type: 'BLOCKED_URL',
                            platform: 'FACEBOOK',
                            description: sprintf('This URL is blocked by Facebook: %s', $errorMessage),
                            url: $normalizedUrl,
                            metadata: $data['error']
                        );

                        $result->addThreat($this->getName(), $threat);
                    }
                }

                // Check if the share is restricted
                if (isset($data['share']) && isset($data['share']['error'])) {
                    $threat = new Threat(
                        type: 'RESTRICTED_URL',
                        platform: 'FACEBOOK',
                        description: 'This URL has sharing restrictions on Facebook',
                        url: $normalizedUrl,
                        metadata: $data['share']
                    );

                    $result->addThreat($this->getName(), $threat);
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with Facebook: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }

    /**
     * Determine if a Facebook API error indicates a security issue.
     *
     * @param array<string, mixed> $error
     * @return bool
     */
    private function isSecurityError(array $error): bool
    {
        $securityKeywords = ['spam', 'abuse', 'malicious', 'unsafe', 'blocked', 'restricted'];
        $message = strtolower($error['message'] ?? '');

        foreach ($securityKeywords as $keyword) {
            if (str_contains($message, $keyword)) {
                return true;
            }
        }

        // Facebook error code 368 = temporarily blocked for policies
        // Facebook error code 1609005 = link blocked
        $blockedCodes = [368, 1609005];

        return in_array($error['code'] ?? 0, $blockedCodes, true);
    }
}
