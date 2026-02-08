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

final class PhishTankProvider extends AbstractProvider
{
    private const API_URL = 'https://checkurl.phishtank.com/checkurl/';

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
        return 'phishtank';
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
                $body = http_build_query([
                    'url' => $normalizedUrl,
                    'format' => 'json',
                    'app_key' => $this->apiKey
                ]);

                $request = $this->requestFactory->createRequest('POST', self::API_URL)
                    ->withHeader('Content-Type', 'application/x-www-form-urlencoded');

                $request = $request->withBody(
                    $this->streamFactory->createStream($body)
                );

                $response = $this->httpClient->sendRequest($request);
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

                if (isset($data['results']['in_database']) && $data['results']['in_database'] === true) {
                    $threat = new Threat(
                        type: 'PHISHING',
                        platform: 'ANY_PLATFORM',
                        description: sprintf(
                            'This URL has been identified as a phishing site by PhishTank. Verified: %s',
                            isset($data['results']['verified']) && $data['results']['verified'] ? 'Yes' : 'No'
                        ),
                        url: $normalizedUrl,
                        metadata: [
                            'phish_id' => $data['results']['phish_id'] ?? null,
                            'verified' => $data['results']['verified'] ?? false,
                            'verified_at' => $data['results']['verified_at'] ?? null,
                            'valid' => $data['results']['valid'] ?? false
                        ]
                    );

                    $result->addThreat($this->getName(), $threat);
                }

                return $result;
            });
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with PhishTank: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }
    }
}
