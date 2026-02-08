<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Qdenka\UltimateLinkChecker\Contract\AbstractProvider;
use Qdenka\UltimateLinkChecker\Exception\ProviderException;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use Qdenka\UltimateLinkChecker\Result\Threat;

final class VirusTotalProvider extends AbstractProvider
{
    private const API_URL = 'https://www.virustotal.com/api/v3/urls';

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
        return 'virustotal';
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
                $urlId = $this->submitUrl($normalizedUrl);
                $analysisResult = $this->getAnalysisResults($urlId);

                if ($analysisResult['data']['attributes']['stats']['malicious'] > 0 ||
                    $analysisResult['data']['attributes']['stats']['suspicious'] > 0) {

                    $threat = new Threat(
                        type: 'MALICIOUS_URL',
                        platform: 'ANY_PLATFORM',
                        description: $this->buildThreatDescription($analysisResult),
                        url: $normalizedUrl,
                        metadata: [
                            'stats' => $analysisResult['data']['attributes']['stats'],
                            'analysis_date' => $analysisResult['data']['attributes']['last_analysis_date'] ?? null,
                            'vendors' => $this->extractMaliciousVendors($analysisResult)
                        ]
                    );

                    $result->addThreat($this->getName(), $threat);
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with VirusTotal: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }

    /**
     * @param string $url
     * @throws ClientExceptionInterface
     * @throws ProviderException
     * @throws \JsonException
     * @return string
     */
    private function submitUrl(string $url): string
    {
        $request = $this->requestFactory->createRequest('POST', self::API_URL)
            ->withHeader('x-apikey', $this->apiKey)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $request = $request->withBody(
            $this->streamFactory->createStream('url=' . urlencode($url))
        );

        $response = $this->httpClient->sendRequest($request);
        $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

        if (!isset($data['data']['id'])) {
            throw new ProviderException('Failed to submit URL to VirusTotal');
        }

        return $data['data']['id'];
    }

    /**
     * @param string $urlId
     * @throws \JsonException
     * @throws ClientExceptionInterface
     * @return array<string, mixed>
     */
    private function getAnalysisResults(string $urlId): array
    {
        $request = $this->requestFactory->createRequest('GET', self::API_URL . '/' . $urlId)
            ->withHeader('x-apikey', $this->apiKey);

        $response = $this->httpClient->sendRequest($request);

        return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $analysisResult
     * @return string
     */
    private function buildThreatDescription(array $analysisResult): string
    {
        $stats = $analysisResult['data']['attributes']['stats'];
        $maliciousCount = $stats['malicious'] ?? 0;
        $suspiciousCount = $stats['suspicious'] ?? 0;
        $totalCount = array_sum($stats);

        $vendorNames = $this->extractMaliciousVendors($analysisResult);
        $vendorString = implode(', ', array_slice($vendorNames, 0, 3));

        if (count($vendorNames) > 3) {
            $vendorString .= ' and others';
        }

        return sprintf(
            'This URL was flagged by %d out of %d security vendors as malicious or suspicious. Detected by: %s',
            $maliciousCount + $suspiciousCount,
            $totalCount,
            $vendorString
        );
    }

    /**
     * @param array<string, mixed> $analysisResult
     * @return array<string>
     */
    private function extractMaliciousVendors(array $analysisResult): array
    {
        $maliciousVendors = [];
        $results = $analysisResult['data']['attributes']['last_analysis_results'] ?? [];

        foreach ($results as $vendorName => $vendorResult) {
            if (($vendorResult['category'] === 'malicious' || $vendorResult['category'] === 'suspicious') &&
                $vendorResult['result'] !== 'clean') {
                $maliciousVendors[] = $vendorName;
            }
        }

        return $maliciousVendors;
    }
}
