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

final class IPQualityScoreProvider extends AbstractProvider
{
    private const API_URL = 'https://www.ipqualityscore.com/api/json/url';

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
        return 'ipqualityscore';
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
                $request = $this->requestFactory->createRequest(
                    'GET',
                    self::API_URL . '/' . $this->apiKey . '/' . urlencode($normalizedUrl)
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                if (isset($data['unsafe']) && $data['unsafe'] === true) {
                    $threatTypes = [];

                    if (!empty($data['phishing'])) {
                        $threatTypes[] = 'PHISHING';
                    }

                    if (!empty($data['malware'])) {
                        $threatTypes[] = 'MALWARE';
                    }

                    if (!empty($data['suspicious'])) {
                        $threatTypes[] = 'SUSPICIOUS';
                    }

                    if (!empty($data['spamming'])) {
                        $threatTypes[] = 'SPAM';
                    }

                    $threat = new Threat(
                        type: !empty($threatTypes) ? $threatTypes[0] : 'UNSAFE',
                        platform: 'ANY_PLATFORM',
                        description: sprintf(
                            'This URL has been flagged as unsafe by IPQualityScore. Risk score: %d/100. Categories: %s',
                            $data['risk_score'] ?? 0,
                            implode(', ', $threatTypes) ?: 'UNSAFE'
                        ),
                        url: $normalizedUrl,
                        metadata: [
                            'risk_score' => $data['risk_score'] ?? null,
                            'domain' => $data['domain'] ?? null,
                            'ip_address' => $data['ip_address'] ?? null,
                            'categories' => $threatTypes,
                            'adult' => $data['adult'] ?? false,
                            'parking' => $data['parking'] ?? false,
                        ]
                    );

                    $result->addThreat($this->getName(), $threat);
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with IPQualityScore: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }
}
