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

final class GoogleSafeBrowsingProvider extends AbstractProvider
{
    private const API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

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
        return 'google_safebrowsing';
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
                $payload = $this->buildRequestPayload([$normalizedUrl]);
                $request = $this->requestFactory->createRequest('POST', $this->getApiUrl())
                    ->withHeader('Content-Type', 'application/json');

                $request = $request->withBody(
                    $this->streamFactory->createStream(json_encode($payload, JSON_THROW_ON_ERROR))
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                if (isset($data['matches']) && is_array($data['matches'])) {
                    foreach ($data['matches'] as $match) {
                        $threat = new Threat(
                            type: $match['threatType'] ?? 'UNKNOWN',
                            platform: $match['platformType'] ?? 'ANY_PLATFORM',
                            description: $this->getThreatDescription($match['threatType'] ?? 'UNKNOWN'),
                            url: $match['threat']['url'] ?? $normalizedUrl,
                            metadata: $match
                        );

                        $result->addThreat($this->getName(), $threat);
                    }
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with Google Safe Browsing: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }

    /**
     * @param array<string> $urls
     * @return array<string, mixed>
     */
    private function buildRequestPayload(array $urls): array
    {
        $threatInfo = [
            'threatTypes' => [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => []
        ];

        foreach ($urls as $url) {
            $threatInfo['threatEntries'][] = ['url' => $url];
        }

        return [
            'client' => [
                'clientId' => 'ultimatelinkchecker',
                'clientVersion' => '1.0.0'
            ],
            'threatInfo' => $threatInfo
        ];
    }

    /**
     * @return string
     */
    private function getApiUrl(): string
    {
        return self::API_URL . '?key=' . $this->apiKey;
    }

    /**
     * @param string $threatType
     * @return string
     */
    private function getThreatDescription(string $threatType): string
    {
        return match ($threatType) {
            'MALWARE' => 'This URL contains malware',
            'SOCIAL_ENGINEERING' => 'This URL contains phishing or social engineering content',
            'UNWANTED_SOFTWARE' => 'This URL contains unwanted software',
            'POTENTIALLY_HARMFUL_APPLICATION' => 'This URL contains a potentially harmful application',
            default => 'This URL has been identified as unsafe'
        };
    }
}
