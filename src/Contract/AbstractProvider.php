<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Contract;

use JetBrains\PhpStorm\Pure;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Qdenka\UltimateLinkChecker\Result\CheckResult;

abstract class AbstractProvider implements ProviderInterface
{
    public function __construct(
        protected readonly string $apiKey,
        protected readonly ?ClientInterface $httpClient = null,
        protected readonly ?RequestFactoryInterface $requestFactory = null,
        protected readonly ?StreamFactoryInterface $streamFactory = null
    ) {
    }

    /**
     * @param array<string> $urls
     * @return array<string, CheckResult>
     */
    public function checkBatch(array $urls): array
    {
        $results = [];

        foreach ($urls as $url) {
            $results[$url] = $this->check($url);
        }

        return $results;
    }

    /**
     * @param string $url
     * @return string
     */
    protected function normalizeUrl(string $url): string
    {
        if (!preg_match('~^(?:f|ht)tps?://~i', $url)) {
            $url = 'http://' . $url;
        }

        return trim($url);
    }

    /**
     * @param string $url
     * @return CheckResult
     */
    #[Pure] protected function createResult(string $url): CheckResult
    {
        return new CheckResult($url);
    }
}
