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
    private const API_URL = 'https://ipqualityscore.com/api/json/url/%s/%s';

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
     * @return CheckResult
     * @throws ProviderException
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            return $this->executeWithRetry(function () use ($normalizedUrl, $result): CheckResult {
                $apiUrl = sprintf(self::API_URL, $this->apiKey, urlencode($normalizedUrl));
                $request = $this->requestFactory->createRequest('GET', $apiUrl);
                $response = $this->httpClient->sendRequest($request);

                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                if (!isset($data['success']) || $data['success'] !== true) {
                    throw new ProviderException(
                        sprintf('IPQualityScore API error: %s', $data['message'] ?? 'Unknown error')
                    );
                }

                $isSuspicious = $data['suspicious'] ?? false;
                $isPhishing = $data['phishing'] ?? false;
                $isMalware = $data['malware'] ?? false;
                $isSpamming = $data['spamming'] ?? false;
                $isUnsafe = $data['unsafe'] ?? false;

                if ($isSuspicious || $isPhishing || $isMalware || $isSpamming || $isUnsafe) {
                    $threatType = $this->determineThreatType($data);

                    $threat = new Threat(
                        type: $threatType,
                        platform: 'ANY_PLATFORM',
                        description: $this->getThreatDescription($threatType),
                        url: $normalizedUrl,
                        metadata: $data
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

    /**
     * Determine the most severe threat type from the response
     *
     * @param array<string, mixed> $data
     * @return string
     */
    private function determineThreatType(array $data): string
    {
        if ($data['malware'] ?? false) {
            return 'MALWARE';
        }

        if ($data['phishing'] ?? false) {
            return 'PHISHING';
        }

        if ($data['parking'] ?? false) {
            return 'PARKING_DOMAIN';
        }

        if ($data['spamming'] ?? false) {
            return 'SPAM';
        }

        if ($data['suspicious'] ?? false) {
            return 'SUSPICIOUS';
        }

        return 'UNSAFE';
    }

    /**
     * Get a human-readable description of the threat
     *
     * @param string $threatType
     * @return string
     */
    private function getThreatDescription(string $threatType): string
    {
        return match ($threatType) {
            'MALWARE' => 'This URL contains or distributes malware',
            'PHISHING' => 'This URL is a phishing site designed to steal sensitive information',
            'PARKING_DOMAIN' => 'This domain is parked and may contain misleading ads',
            'SPAM' => 'This URL is associated with spam or unwanted communications',
            'SUSPICIOUS' => 'This URL exhibits suspicious characteristics',
            'UNSAFE' => 'This URL was identified as unsafe',
            default => 'This URL was flagged as potentially harmful'
        };
    }
}
