<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Factory;

use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Exception\InvalidArgumentException;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\IPQualityScoreProvider;
use Qdenka\UltimateLinkChecker\Provider\PhishTankProvider;
use Qdenka\UltimateLinkChecker\Provider\VirusTotalProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;

final class ProviderFactory
{
    /**
     * @param string $name
     * @param string $apiKey
     * @return ProviderInterface
     * @throws InvalidArgumentException
     */
    public static function createProvider(string $name, string $apiKey): ProviderInterface
    {
        return match ($name) {
            'google_safebrowsing' => new GoogleSafeBrowsingProvider($apiKey),
            'yandex_safebrowsing' => new YandexSafeBrowsingProvider($apiKey),
            'virustotal' => new VirusTotalProvider($apiKey),
            'phishtank' => new PhishTankProvider($apiKey),
            'ipqualityscore' => new IPQualityScoreProvider($apiKey),
            default => throw new InvalidArgumentException(sprintf('Unknown provider "%s"', $name)),
        };
    }

    /**
     * Get a list of available provider names
     *
     * @return array<string>
     */
    public static function getAvailableProviders(): array
    {
        return [
            'google_safebrowsing',
            'yandex_safebrowsing',
            'virustotal',
            'phishtank',
            'ipqualityscore',
        ];
    }
}
