<?php

namespace QDenka\UltimateLinkChecker\Infrastructure\Service;

use QDenka\UltimateLinkChecker\Domain\Model\Link;
use QDenka\UltimateLinkChecker\Domain\Service\LinkCheckerServiceInterface;
use Symfony\Component\Config\Definition\Exception\Exception;
use GuzzleHttp\Client;

class GoogleSafeBrowsingLinkCheckerService implements LinkCheckerServiceInterface
{
    private Client $client;
    private string $apiKey;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
        $this->client = new Client([
            'base_uri' => 'https://safebrowsing.googleapis.com/v4/',
        ]);
    }

    public function checkLink(Link $link): void
    {
        $response = $this->client->post('threatMatches:find', [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'query' => [
                'key' => $this->apiKey,
            ],
            'json' => [
                'threatInfo' => [
                    'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    'platformTypes' => ['ANY_PLATFORM'],
                    'threatEntryTypes' => ['URL'],
                    'threatEntries' => [
                        ['url' => $link->getUrl()],
                    ],
                ],
            ],
        ]);

        $body = json_decode((string) $response->getBody(), true);

        if (isset($body['matches'])) {
            $link->setBlocked(true);
        }
    }
}