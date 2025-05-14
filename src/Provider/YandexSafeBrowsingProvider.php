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

final class YandexSafeBrowsingProvider extends AbstractProvider
{
    private const API_URL = 'https://sba.yandex.net/v4/threatMatches:find';

    public function __construct(
        string $apiKey,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null
    ) {
        parent::__construct(
            $apiKey,
            $httpClient ?? new Client(),
            $requestFactory ?? new HttpFactory(),
            $streamFactory ?? new HttpFactory()
        );
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'yandex_safebrowsing';
    }

    /**
     * @param string $url
     * @return CheckResult
     * @throws ProviderException
     * @throws \JsonException
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            $payload = $this->buildRequestPayload([$normalizedUrl]);
            $request = $this->requestFactory->createRequest('POST', $this->getApiUrl())
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Authorization', 'ApiKey ' . $this->apiKey);

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
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with Yandex Safe Browsing: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }

        return $result;
    }

    /**
     * @param array<string> $urls
     * @return array<string, mixed>
     */
    private function buildRequestPayload(array $urls): array
    {
        $threatEntries = [];
        foreach ($urls as $url) {
            $threatEntries[] = ['url' => $url];
        }

        return [
            'client' => [
                'clientId' => 'ultimatelinkchecker',
                'clientVersion' => '1.0.0'
            ],
            'threatInfo' => [
                'threatTypes' => [
                    'MALWARE',
                    'SOCIAL_ENGINEERING',
                    'UNWANTED_SOFTWARE',
                    'HARMFUL_DOWNLOAD'
                ],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => $threatEntries
            ]
        ];
    }

    /**
     * @return string
     */
    private function getApiUrl(): string
    {
        return self::API_URL;
    }

    /**
     * @param string $threatType
     * @return string
     */
    private function getThreatDescription(string $threatType): string
    {
        return match ($threatType) {
            'MALWARE' => 'This URL contains malware according to Yandex',
            'SOCIAL_ENGINEERING' => 'This URL contains phishing or social engineering content according to Yandex',
            'UNWANTED_SOFTWARE' => 'This URL contains unwanted software according to Yandex',
            'HARMFUL_DOWNLOAD' => 'This URL leads to harmful downloads according to Yandex',
            default => 'This URL has been identified as unsafe by Yandex'
        };
    }
}
