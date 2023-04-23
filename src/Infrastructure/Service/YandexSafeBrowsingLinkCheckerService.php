<?php

namespace QDenka\UltimateLinkChecker\Service;

use QDenka\UltimateLinkChecker\Exception\LinkCheckerException;

class YandexSafeBrowsingLinkCheckerService implements LinkCheckerServiceInterface
{
    private string $apiKey;

    public function __construct(string $apiKey)
    {
        $this->apiKey = $apiKey;
    }

    /**
     * @inheritDoc
     */
    public function checkUrl(string $url): array
    {
        // Отправляем запрос к Yandex SafeBrowsing API с помощью GuzzleHttp
        // и получаем результат в виде JSON
        $client = new \GuzzleHttp\Client();
        $response = $client->get("https://safebrowsing.api.yandex.net/v4/lookup?url={$url}&apikey={$this->apiKey}");
        $json = (string) $response->getBody();

        // Декодируем JSON и возвращаем результат в виде массива
        $data = json_decode($json, true);

        if (!isset($data['matches'])) {
            throw new LinkCheckerException('Error occurred while checking link with Yandex SafeBrowsing API');
        }

        $result = [];

        foreach ($data['matches'] as $match) {
            $result[] = [
                'threat_type' => $match['threatType'],
                'platform_type' => $match['platformType'],
                'threat_entry_type' => $match['threatEntryType'],
                'threat' => $match['threat'],
                'cache_duration' => $match['cacheDuration'],
            ];
        }

        return $result;
    }
}
