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
 * Uses the Facebook Graph API v18.0 to check if a URL is safe for sharing.
 * Requires a valid Facebook App access token.
 */
final class FacebookProvider extends AbstractProvider
{
    private const API_URL = 'https://graph.facebook.com/v18.0';

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
     * @throws ProviderException
     * @return CheckResult
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            return $this->executeWithRetry(function () use ($normalizedUrl, $result): CheckResult {
                $encodedUrl = urlencode($normalizedUrl);
                $apiUrl = sprintf(
                    '%s/?id=%s&scrape=true&access_token=%s',
                    self::API_URL,
                    $encodedUrl,
                    $this->apiKey
                );

                $request = $this->requestFactory->createRequest('POST', $apiUrl);

                $response = $this->httpClient->sendRequest($request);
                $statusCode = $response->getStatusCode();
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                // Facebook returns error for blocked/restricted URLs
                if ($statusCode >= 400 || isset($data['error'])) {
                    $errorMessage = $data['error']['message'] ?? 'URL blocked by Facebook';
                    $errorCode = $data['error']['code'] ?? 0;

                    // Error code 100 with specific subcode indicates URL restriction
                    $isBlocked = ($errorCode === 100) ||
                        str_contains(strtolower($errorMessage), 'blocked') ||
                        str_contains(strtolower($errorMessage), 'restricted') ||
                        str_contains(strtolower($errorMessage), 'spam') ||
                        str_contains(strtolower($errorMessage), 'unsafe');

                    if ($isBlocked) {
                        $threat = new Threat(
                            type: 'BLOCKED_URL',
                            platform: 'FACEBOOK',
                            description: sprintf(
                                'This URL is blocked or restricted on Facebook: %s',
                                $errorMessage
                            ),
                            url: $normalizedUrl,
                            metadata: [
                                'error_code' => $errorCode,
                                'error_subcode' => $data['error']['error_subcode'] ?? null,
                                'error_message' => $errorMessage,
                            ]
                        );

                        $result->addThreat($this->getName(), $threat);
                    }
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
}
