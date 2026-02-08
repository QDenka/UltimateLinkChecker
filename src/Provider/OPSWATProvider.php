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
 * OPSWAT MetaDefender URL reputation provider.
 *
 * Uses the OPSWAT MetaDefender Cloud API v4 to check URL reputation.
 * Requires a valid MetaDefender Cloud API key.
 */
final class OPSWATProvider extends AbstractProvider
{
    private const API_URL = 'https://api.metadefender.com/v4/url';

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
        return 'opswat';
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
                $payload = json_encode(['url' => $normalizedUrl], JSON_THROW_ON_ERROR);

                $request = $this->requestFactory->createRequest('POST', self::API_URL)
                    ->withHeader('apikey', $this->apiKey)
                    ->withHeader('Content-Type', 'application/json');

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
                sprintf('Error checking URL with OPSWAT MetaDefender: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }

    /**
     * Process OPSWAT API results and add threats if found.
     *
     * @param array<string, mixed> $data
     * @param string $url
     * @param CheckResult $result
     */
    private function processResults(array $data, string $url, CheckResult $result): void
    {
        // OPSWAT returns lookup_results with detected_by count
        $lookupResults = $data['lookup_results'] ?? [];
        $detectedBy = $lookupResults['detected_by'] ?? 0;

        if ($detectedBy > 0) {
            $sources = $lookupResults['sources'] ?? [];
            $maliciousSources = [];

            foreach ($sources as $source) {
                $assessment = $source['assessment'] ?? '';
                if (in_array($assessment, ['malware', 'phishing', 'suspicious', 'spam', 'potentially_malicious'], true)) {
                    $maliciousSources[] = [
                        'provider' => $source['provider'] ?? 'unknown',
                        'assessment' => $assessment,
                    ];
                }
            }

            if (!empty($maliciousSources)) {
                $threatType = $this->determineThreatType($maliciousSources);
                $providerNames = array_map(fn (array $s) => $s['provider'], $maliciousSources);

                $threat = new Threat(
                    type: $threatType,
                    platform: 'ANY_PLATFORM',
                    description: sprintf(
                        'This URL was flagged by %d source(s) in OPSWAT MetaDefender: %s',
                        count($maliciousSources),
                        implode(', ', array_slice($providerNames, 0, 5))
                    ),
                    url: $url,
                    metadata: [
                        'detected_by' => $detectedBy,
                        'sources' => $maliciousSources,
                        'start_time' => $data['lookup_results']['start_time'] ?? null,
                    ]
                );

                $result->addThreat($this->getName(), $threat);
            }
        }
    }

    /**
     * Determine the primary threat type from malicious sources.
     *
     * @param array<array{provider: string, assessment: string}> $sources
     * @return string
     */
    private function determineThreatType(array $sources): string
    {
        $assessments = array_column($sources, 'assessment');

        if (in_array('malware', $assessments, true)) {
            return 'MALWARE';
        }

        if (in_array('phishing', $assessments, true)) {
            return 'PHISHING';
        }

        if (in_array('spam', $assessments, true)) {
            return 'SPAM';
        }

        return 'SUSPICIOUS';
    }
}
