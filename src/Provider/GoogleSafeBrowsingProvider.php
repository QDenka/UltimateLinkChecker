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
     * @throws ProviderException
     * @return CheckResult
     */
    public function check(string $url): CheckResult
    {
        $normalizedUrl = $this->normalizeUrl($url);
        $result = $this->createResult($normalizedUrl);

        try {
            return $this->executeWithRetry(function () use ($normalizedUrl, $result): CheckResult {
                $payload = json_encode([
                    'client' => [
                        'clientId' => 'ultimatelinkchecker',
                        'clientVersion' => '1.0.0'
                    ],
                    'threatInfo' => [
                        'threatTypes' => [
                            'MALWARE',
                            'SOCIAL_ENGINEERING',
                            'UNWANTED_SOFTWARE',
                            'POTENTIALLY_HARMFUL_APPLICATION',
                            'THREAT_TYPE_UNSPECIFIED'
                        ],
                        'platformTypes' => ['ANY_PLATFORM'],
                        'threatEntryTypes' => ['URL'],
                        'threatEntries' => [
                            ['url' => $normalizedUrl]
                        ]
                    ]
                ], JSON_THROW_ON_ERROR);

                $request = $this->requestFactory->createRequest('POST', self::API_URL . '?key=' . $this->apiKey)
                    ->withHeader('Content-Type', 'application/json');

                $request = $request->withBody(
                    $this->streamFactory->createStream($payload)
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                if (!empty($data['matches'])) {
                    foreach ($data['matches'] as $match) {
                        $threat = new Threat(
                            type: $match['threatType'] ?? 'UNKNOWN',
                            platform: $match['platformType'] ?? 'ANY_PLATFORM',
                            description: sprintf(
                                'This URL has been flagged by Google Safe Browsing as %s',
                                $match['threatType'] ?? 'UNKNOWN'
                            ),
                            url: $normalizedUrl,
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
}
