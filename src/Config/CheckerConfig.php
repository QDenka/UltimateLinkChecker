<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Config;

use Psr\SimpleCache\CacheInterface;
use Qdenka\UltimateLinkChecker\Cache\NullCacheAdapter;

final class CheckerConfig
{
    /**
     * @var CacheInterface|NullCacheAdapter|null
     */
    private CacheInterface|NullCacheAdapter|null $cacheAdapter = null;
    /**
     * @var int
     */
    private int $cacheTtl = 3600;
    /**
     * @var bool
     */
    private bool $cacheEnabled = false;
    /**
     * @var float
     */
    private float $timeout = 5.0;
    /**
     * @var int
     */
    private int $retries = 1;
    /**
     * @var bool
     */
    private bool $logEnabled = false;

    public function __construct()
    {
        $this->cacheAdapter = new NullCacheAdapter();
    }

    /**
     * @param CacheInterface|null $cacheAdapter
     * @return $this
     */
    public function setCacheAdapter(?CacheInterface $cacheAdapter): self
    {
        $this->cacheAdapter = $cacheAdapter;
        $this->cacheEnabled = $cacheAdapter !== null;

        return $this;
    }

    /**
     * @return CacheInterface|null
     */
    public function getCacheAdapter(): ?CacheInterface
    {
        return $this->cacheAdapter;
    }

    /**
     * @param int $cacheTtl
     * @return $this
     */
    public function setCacheTtl(int $cacheTtl): self
    {
        $this->cacheTtl = $cacheTtl;

        return $this;
    }

    /**
     * @return int
     */
    public function getCacheTtl(): int
    {
        return $this->cacheTtl;
    }

    /**
     * @param bool $enabled
     * @return $this
     */
    public function enableCache(bool $enabled = true): self
    {
        $this->cacheEnabled = $enabled;

        return $this;
    }

    /**
     * @return bool
     */
    public function isCacheEnabled(): bool
    {
        return $this->cacheEnabled && $this->cacheAdapter !== null;
    }

    /**
     * @param float $timeout
     * @return $this
     */
    public function setTimeout(float $timeout): self
    {
        $this->timeout = $timeout;

        return $this;
    }

    /**
     * @return float
     */
    public function getTimeout(): float
    {
        return $this->timeout;
    }

    /**
     * @param int $retries
     * @return $this
     */
    public function setRetries(int $retries): self
    {
        $this->retries = $retries;

        return $this;
    }

    /**
     * @return int
     */
    public function getRetries(): int
    {
        return $this->retries;
    }

    /**
     * @param bool $enabled
     * @return $this
     */
    public function enableLog(bool $enabled = true): self
    {
        $this->logEnabled = $enabled;

        return $this;
    }

    /**
     * @return bool
     */
    public function isLogEnabled(): bool
    {
        return $this->logEnabled;
    }
}
