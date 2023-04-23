<?php

namespace QDenka\UltimateLinkChecker;

use GuzzleHttp\ClientInterface;
use QDenka\UltimateLinkChecker\Domain\Service\LinkCheckerServiceInterface;

class FacebookLinkCheckerService implements LinkCheckerServiceInterface
{
    private $client;
    private $url;

    public function __construct(ClientInterface $client)
    {
        $this->client = $client;
        $this->url = 'https://graph.facebook.com/v11.0';
    }

    public function checkLink($link)
    {
        $params = [
            'id' => $link,
            'fields' => 'engagement'
        ];

        $response = $this->client->get($this->url . '?' . http_build_query($params));
        $result = json_decode($response->getBody(), true);

        return isset($result['engagement']) && $result['engagement']['reaction_count'] === 0;
    }
}
