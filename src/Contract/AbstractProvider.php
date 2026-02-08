<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Contract;

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
        protected readonly ?StreamFactoryInterface $streamFactory = null,
        protected readonly float $timeout = 5.0,
        protected readonly int $retries = 1
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
    protected function createResult(string $url): CheckResult
    {
        return new CheckResult($url);
    }

    /**
     * Execute an HTTP request with retry logic.
     *
     * @param callable $requestCallable A callable that performs the HTTP request and returns a result.
     * @return mixed The result of the callable.
     * @throws \Throwable Re-throws the last exception if all retries fail.
     */
    protected function executeWithRetry(callable $requestCallable): mixed
    {
        $lastException = null;

        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                return $requestCallable();
            } catch (\Throwable $e) {
                $lastException = $e;
                if ($attempt < $this->retries) {
                    usleep(100_000 * ($attempt + 1)); // Incremental backoff
                }
            }
        }

        throw $lastException;
    }
}
