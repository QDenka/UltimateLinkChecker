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
 * Cisco Talos Intelligence URL reputation provider.
 *
 * Uses the Cisco Talos API to check domain/URL reputation.
 * Requires a valid Cisco Talos API key.
 */
final class CiscoTalosProvider extends AbstractProvider
{
    private const API_URL = 'https://cloud-intel.api.cisco.com/v1/url/reputation';

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
        return 'cisco_talos';
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
                $domain = parse_url($normalizedUrl, PHP_URL_HOST) ?: $normalizedUrl;
                $payload = json_encode(['url' => $domain], JSON_THROW_ON_ERROR);

                $request = $this->requestFactory->createRequest('POST', self::API_URL)
                    ->withHeader('Authorization', 'Bearer ' . $this->apiKey)
                    ->withHeader('Content-Type', 'application/json');

                $request = $request->withBody(
                    $this->streamFactory->createStream($payload)
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                $reputation = $data['reputation'] ?? $data['web_reputation'] ?? null;

                $isMalicious = false;
                $threatCategories = [];

                if (is_array($reputation)) {
                    $score = $reputation['score'] ?? $reputation['threat_score'] ?? null;
                    // Talos scores: negative = bad reputation
                    if ($score !== null && $score < -5) {
                        $isMalicious = true;
                    }

                    $categories = $reputation['categories'] ?? $data['categories'] ?? [];
                    $dangerousCategories = [
                        'malware', 'phishing', 'botnet', 'spam',
                        'suspicious', 'untrusted', 'compromised',
                    ];

                    foreach ($categories as $category) {
                        $categoryName = is_array($category) ? ($category['name'] ?? '') : (string) $category;
                        if (in_array(strtolower($categoryName), $dangerousCategories, true)) {
                            $isMalicious = true;
                            $threatCategories[] = $categoryName;
                        }
                    }
                } elseif (is_numeric($reputation)) {
                    if ((float) $reputation < -5) {
                        $isMalicious = true;
                    }
                }

                if ($isMalicious) {
                    $threat = new Threat(
                        type: !empty($threatCategories) ? strtoupper($threatCategories[0]) : 'MALICIOUS_REPUTATION',
                        platform: 'ANY_PLATFORM',
                        description: sprintf(
                            'This URL/domain has a poor reputation score on Cisco Talos%s',
                            !empty($threatCategories) ? ': ' . implode(', ', $threatCategories) : ''
                        ),
                        url: $normalizedUrl,
                        metadata: [
                            'domain' => $domain,
                            'reputation' => $reputation,
                            'categories' => $threatCategories,
                        ]
                    );

                    $result->addThreat($this->getName(), $threat);
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with Cisco Talos: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }
}
