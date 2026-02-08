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
 * Cisco Talos Intelligence provider.
 *
 * Uses the Cisco Talos reputation lookup API to check URL/domain reputation.
 * Requires a valid Cisco Talos API key.
 */
final class CiscoTalosProvider extends AbstractProvider
{
    private const API_URL = 'https://talosintelligence.com/api/v2/url/reputation';

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
     * @return CheckResult
     * @throws ProviderException
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            return $this->executeWithRetry(function () use ($normalizedUrl, $result): CheckResult {
                $domain = $this->extractDomain($normalizedUrl);

                $payload = json_encode(['url' => $domain], JSON_THROW_ON_ERROR);

                $request = $this->requestFactory->createRequest('POST', self::API_URL)
                    ->withHeader('Content-Type', 'application/json')
                    ->withHeader('Authorization', 'Bearer ' . $this->apiKey);

                $request = $request->withBody(
                    $this->streamFactory->createStream($payload)
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                $this->processResults($data, $normalizedUrl, $result);

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

    /**
     * Process Cisco Talos API results and add threats if found.
     *
     * @param array<string, mixed> $data
     * @param string $url
     * @param CheckResult $result
     */
    private function processResults(array $data, string $url, CheckResult $result): void
    {
        $reputation = $data['reputation'] ?? null;
        $categories = $data['categories'] ?? [];

        // Cisco Talos reputation: "poor" or "very_poor" means dangerous
        $dangerousReputations = ['poor', 'very_poor', 'untrusted'];
        $dangerousCategories = [
            'malware', 'phishing', 'spam', 'botnets',
            'exploit_kit', 'ransomware', 'cryptomining'
        ];

        $isDangerous = in_array(strtolower((string) $reputation), $dangerousReputations, true);

        $matchedCategories = [];
        foreach ($categories as $category) {
            $categoryName = strtolower(is_array($category) ? ($category['name'] ?? '') : (string) $category);
            if (in_array($categoryName, $dangerousCategories, true)) {
                $matchedCategories[] = $categoryName;
                $isDangerous = true;
            }
        }

        if ($isDangerous) {
            $threatType = $this->determineThreatType($matchedCategories, (string) $reputation);

            $threat = new Threat(
                type: $threatType,
                platform: 'ANY_PLATFORM',
                description: sprintf(
                    'Cisco Talos rates this URL with reputation "%s"%s',
                    $reputation ?? 'unknown',
                    !empty($matchedCategories) ? ' (categories: ' . implode(', ', $matchedCategories) . ')' : ''
                ),
                url: $url,
                metadata: [
                    'reputation' => $reputation,
                    'categories' => $categories,
                    'matched_categories' => $matchedCategories,
                ]
            );

            $result->addThreat($this->getName(), $threat);
        }
    }

    /**
     * Determine the primary threat type from matched categories.
     *
     * @param array<string> $categories
     * @param string $reputation
     * @return string
     */
    private function determineThreatType(array $categories, string $reputation): string
    {
        if (in_array('malware', $categories, true) || in_array('ransomware', $categories, true)) {
            return 'MALWARE';
        }

        if (in_array('phishing', $categories, true)) {
            return 'PHISHING';
        }

        if (in_array('spam', $categories, true)) {
            return 'SPAM';
        }

        if (in_array('botnets', $categories, true)) {
            return 'BOTNET';
        }

        if (in_array('exploit_kit', $categories, true)) {
            return 'EXPLOIT_KIT';
        }

        if (in_array('cryptomining', $categories, true)) {
            return 'CRYPTOMINING';
        }

        return 'UNTRUSTED';
    }

    /**
     * Extract domain from URL.
     *
     * @param string $url
     * @return string
     */
    private function extractDomain(string $url): string
    {
        $parsed = parse_url($url);

        return $parsed['host'] ?? $url;
    }
}
