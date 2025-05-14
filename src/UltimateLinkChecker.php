<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker;

use Qdenka\UltimateLinkChecker\Config\CheckerConfig;
use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Exception\InvalidArgumentException;
use Qdenka\UltimateLinkChecker\Exception\ProviderNotFoundException;
use Qdenka\UltimateLinkChecker\Result\AggregateResult;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use React\Promise\PromiseInterface;

final class UltimateLinkChecker
{
    public const CONSENSUS_ANY = 'any';
    public const CONSENSUS_ALL = 'all';
    public const CONSENSUS_MAJORITY = 'majority';

    /** @var array<string, ProviderInterface> */
    private array $providers = [];

    public function __construct(
        private readonly CheckerConfig $config = new CheckerConfig(),
    ) {
    }

    /**
     * @param ProviderInterface $provider
     * @return $this
     */
    public function addProvider(ProviderInterface $provider): self
    {
        $this->providers[$provider->getName()] = $provider;
        return $this;
    }

    /**
     * @param string $providerName
     * @return $this
     */
    public function removeProvider(string $providerName): self
    {
        if (isset($this->providers[$providerName])) {
            unset($this->providers[$providerName]);
        }

        return $this;
    }

    /**
     * @return array<string, ProviderInterface>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    /**
     * Get a specific provider by name
     *
     * @param string $name
     * @return ProviderInterface
     * @throws ProviderNotFoundException
     */
    public function getProvider(string $name): ProviderInterface
    {
        if (!isset($this->providers[$name])) {
            throw new ProviderNotFoundException(sprintf('Provider "%s" not found', $name));
        }

        return $this->providers[$name];
    }

    /**
     * Check if a URL is safe using all registered providers or specific ones
     *
     * @param string $url
     * @param array<string>|null $providerNames
     * @param string $consensus
     * @return AggregateResult
     * @throws InvalidArgumentException
     * @throws ProviderNotFoundException
     */
    public function check(
        string $url,
        ?array $providerNames = null,
        string $consensus = self::CONSENSUS_ANY
    ): AggregateResult {
        $this->validateProviders($providerNames);
        $this->validateConsensus($consensus);

        $providers = $this->resolveProviders($providerNames);
        $result = new AggregateResult($url);

        foreach ($providers as $providerName => $provider) {
            $providerResult = $this->checkWithProvider($provider, $url);
            $result->addProviderResult($providerName, $providerResult);
        }

        $result->determineOverallSafety($consensus);

        return $result;
    }

    /**
     * Check a batch of URLs
     *
     * @param array<string> $urls
     * @param array<string>|null $providerNames
     * @param string $consensus
     * @return array<string, AggregateResult>
     * @throws InvalidArgumentException
     * @throws ProviderNotFoundException
     */
    public function checkBatch(
        array $urls,
        ?array $providerNames = null,
        string $consensus = self::CONSENSUS_ANY
    ): array {
        $this->validateProviders($providerNames);
        $this->validateConsensus($consensus);

        $results = [];
        foreach ($urls as $url) {
            $results[$url] = $this->check($url, $providerNames, $consensus);
        }

        return $results;
    }

    /**
     * Check a URL asynchronously
     *
     * @param array<string>|null $providerNames
     *
     * @return PromiseInterface<CheckResult>
     */
    public function checkAsync(
        string $url,
        ?array $providerNames = null,
        string $consensus = self::CONSENSUS_ANY
    ): PromiseInterface {
        // The actual implementation would use promises and async requests
        // This is a simplified version that returns a promise that resolves immediately

        return \React\Promise\resolve($this->check($url, $providerNames, $consensus));
    }

    /**
     * Check multiple URLs asynchronously
     *
     * @param array<string> $urls
     * @param array<string>|null $providerNames
     * @return array<string, PromiseInterface>
     */
    public function checkBatchAsync(
        array $urls,
        ?array $providerNames = null,
        string $consensus = self::CONSENSUS_ANY
    ): array {
        $promises = [];

        foreach ($urls as $url) {
            $promises[$url] = $this->checkAsync($url, $providerNames, $consensus);
        }

        return $promises;
    }

    /**
     * Check a URL with a specific provider
     *
     * @param ProviderInterface $provider
     * @param string $url
     *
     * @return CheckResult
     */
    private function checkWithProvider(ProviderInterface $provider, string $url): CheckResult
    {
        $cacheKey = $this->generateCacheKey($provider->getName(), $url);

        if ($this->config->isCacheEnabled()) {
            $cached = $this->config->getCacheAdapter()?->get($cacheKey);

            if ($cached instanceof CheckResult) {
                return $cached;
            }
        }

        $result = $provider->check($url);

        if ($this->config->isCacheEnabled() && $this->config->getCacheAdapter() !== null) {
            $this->config->getCacheAdapter()->set(
                $cacheKey,
                $result,
                $this->config->getCacheTtl()
            );
        }

        return $result;
    }

    /**
     * Generate a cache key for a provider and URL
     *
     * @param string $providerName
     * @param string $url
     *
     * @return string
     */
    private function generateCacheKey(string $providerName, string $url): string
    {
        return sprintf('ultimatelinkchecker:%s:%s', $providerName, md5($url));
    }

    /**
     * Resolve providers based on provider names
     *
     * @param array<string>|null $providerNames
     * @return array<string, ProviderInterface>
     * @throws ProviderNotFoundException
     */
    private function resolveProviders(?array $providerNames = null): array
    {
        if (empty($providerNames)) {
            return $this->providers;
        }

        $providers = [];
        foreach ($providerNames as $name) {
            if (!isset($this->providers[$name])) {
                throw new ProviderNotFoundException(sprintf('Provider "%s" not found', $name));
            }

            $providers[$name] = $this->providers[$name];
        }

        return $providers;
    }

    /**
     * Validate provider names
     *
     * @param array<string>|null $providerNames
     * @throws InvalidArgumentException
     * @throws ProviderNotFoundException
     */
    private function validateProviders(?array $providerNames = null): void
    {
        if (empty($this->providers)) {
            throw new InvalidArgumentException('No providers have been added to the checker');
        }

        if ($providerNames !== null) {
            foreach ($providerNames as $name) {
                if (!isset($this->providers[$name])) {
                    throw new ProviderNotFoundException(sprintf('Provider "%s" not found', $name));
                }
            }
        }
    }

    /**
     * Validate consensus parameter
     *
     * @param string $consensus
     * @throws InvalidArgumentException
     */
    private function validateConsensus(string $consensus): void
    {
        $validConsensus = [self::CONSENSUS_ANY, self::CONSENSUS_ALL, self::CONSENSUS_MAJORITY];

        if (!in_array($consensus, $validConsensus, true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid consensus type "%s". Valid types are: %s',
                    $consensus,
                    implode(', ', $validConsensus)
                )
            );
        }
    }
}
