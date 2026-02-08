<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Factory;

use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Exception\InvalidArgumentException;
use Qdenka\UltimateLinkChecker\Provider\CiscoTalosProvider;
use Qdenka\UltimateLinkChecker\Provider\FacebookProvider;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\IPQualityScoreProvider;
use Qdenka\UltimateLinkChecker\Provider\OPSWATProvider;
use Qdenka\UltimateLinkChecker\Provider\PhishTankProvider;
use Qdenka\UltimateLinkChecker\Provider\VirusTotalProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;

final class ProviderFactory
{
    /**
     * @param string $name
     * @param string $apiKey
     * @param float $timeout
     * @param int $retries
     * @return ProviderInterface
     * @throws InvalidArgumentException
     */
    public static function createProvider(
        string $name,
        string $apiKey,
        float $timeout = 5.0,
        int $retries = 1
    ): ProviderInterface {
        return match ($name) {
            'google_safebrowsing' => new GoogleSafeBrowsingProvider($apiKey, timeout: $timeout, retries: $retries),
            'yandex_safebrowsing' => new YandexSafeBrowsingProvider($apiKey, timeout: $timeout, retries: $retries),
            'virustotal' => new VirusTotalProvider($apiKey, timeout: $timeout, retries: $retries),
            'phishtank' => new PhishTankProvider($apiKey, timeout: $timeout, retries: $retries),
            'ipqualityscore' => new IPQualityScoreProvider($apiKey, timeout: $timeout, retries: $retries),
            'facebook' => new FacebookProvider($apiKey, timeout: $timeout, retries: $retries),
            'opswat' => new OPSWATProvider($apiKey, timeout: $timeout, retries: $retries),
            'cisco_talos' => new CiscoTalosProvider($apiKey, timeout: $timeout, retries: $retries),
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
            'facebook',
            'opswat',
            'cisco_talos',
        ];
    }
}
