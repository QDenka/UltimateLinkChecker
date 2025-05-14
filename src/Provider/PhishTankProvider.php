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
        return 'phishtank';
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
            $formData = [
                'url' => $normalizedUrl,
                'api_key' => $this->apiKey,
                'format' => 'json'
            ];

            $request = $this->requestFactory->createRequest('POST', self::API_URL)
                ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withHeader('User-Agent', 'UltimateLinkChecker/1.0');

            $request = $request->withBody(
                $this->streamFactory->createStream(http_build_query($formData))
            );

            $response = $this->httpClient->sendRequest($request);
            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);

            if (isset($data['results']['in_database']) && $data['results']['in_database'] === true) {
                if (isset($data['results']['phish_detail_page']) && $data['results']['phish']) {
                    $threat = new Threat(
                        type: 'PHISHING',
                        platform: 'ANY_PLATFORM',
                        description: 'This URL was identified as a phishing site by PhishTank',
                        url: $normalizedUrl,
                        metadata: [
                            'phish_id' => $data['results']['phish_id'] ?? null,
                            'verified' => $data['results']['verified'] ?? false,
                            'verified_at' => $data['results']['verified_at'] ?? null,
                            'phish_detail_url' => $data['results']['phish_detail_page'] ?? null
                        ]
                    );

                    $result->addThreat($this->getName(), $threat);
                }
            }
        } catch (GuzzleException $e) {
            throw new ProviderException(
                sprintf('Error checking URL with PhishTank: %s', $e->getMessage()),
                $e->getCode(),
                $e
            );
        }

        return $result;
    }
}
