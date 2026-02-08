<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Contract;

use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Qdenka\UltimateLinkChecker\Result\CheckResult;

abstract class AbstractProvider implements ProviderInterface
{
    protected readonly string $apiKey;
    protected readonly ClientInterface $httpClient;
    protected readonly RequestFactoryInterface $requestFactory;
    protected readonly StreamFactoryInterface $streamFactory;
    protected readonly float $timeout;
    protected readonly int $retries;

    public function __construct(
        string $apiKey,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        float $timeout = 5.0,
        int $retries = 1
    ) {
        $this->apiKey = $apiKey;
        $this->httpClient = $httpClient ?? new \GuzzleHttp\Client(['timeout' => $timeout]);
        $this->requestFactory = $requestFactory ?? new HttpFactory();
        $this->streamFactory = $streamFactory ?? new HttpFactory();
        $this->timeout = $timeout;
        $this->retries = $retries;
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
     * Execute an HTTP request with retry logic.
     *
     * @param callable $requestCallable A callable that performs the HTTP request and returns a result.
     * @throws \Throwable Re-throws the last exception if all retries fail.
     * @return mixed The result of the callable.
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
                    usleep(100000 * ($attempt + 1)); // incremental backoff: 100ms, 200ms, 300ms...
                }
            }
        }

        throw $lastException;
    }

    /**
     * @param string $url
     * @return string
     */
    protected function normalizeUrl(string $url): string
    {
        return trim($url);
    }

    /**
     * @param string $url
     * @return CheckResult
     */
    protected function createResult(string $url): CheckResult
    {
        return new CheckResult($url, $this->getName());
    }
}
