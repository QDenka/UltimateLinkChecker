<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Cache;

use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;
use Redis;

final class RedisCacheAdapter implements CacheInterface
{
    public function __construct(
        private readonly Redis $redis,
        private readonly string $prefix = 'ultimatelinkchecker:'
    ) {
    }

    /**
     * @param string $key
     * @param mixed|null $default
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $value = $this->redis->get($this->getPrefixedKey($key));

        if ($value === false) {
            return $default;
        }

        return unserialize($value, ['allowed_classes' => true]);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @param DateInterval|int|null $ttl
     * @return bool
     */
    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $prefixedKey = $this->getPrefixedKey($key);
        $serialized = serialize($value);

        if ($ttl === null) {
            $result = $this->redis->set($prefixedKey, $serialized);

            return (bool) $result;
        }

        if ($ttl instanceof DateInterval) {
            $ttl = $this->dateIntervalToSeconds($ttl);
        }

        $result = $this->redis->setex($prefixedKey, $ttl, $serialized);

        return (bool) $result;
    }

    /**
     * @param string $key
     * @return bool
     */
    public function delete(string $key): bool
    {
        $result = $this->redis->del($this->getPrefixedKey($key));

        return ((int) $result) > 0;
    }

    /**
     * @return bool
     */
    public function clear(): bool
    {
        $keys = $this->redis->keys($this->prefix . '*');

        if (empty($keys)) {
            return true;
        }

        $result = $this->redis->del($keys);

        return ((int) $result) > 0;
    }

    /**
     * @param iterable $keys
     * @param mixed|null $default
     * @return iterable
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];

        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    /**
     * @param iterable $values
     * @param DateInterval|int|null $ttl
     * @return bool
     */
    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        $success = true;

        foreach ($values as $key => $value) {
            $success = $success && $this->set($key, $value, $ttl);
        }

        return $success;
    }

    /**
     * @param iterable $keys
     * @return bool
     */
    public function deleteMultiple(iterable $keys): bool
    {
        $prefixedKeys = [];

        foreach ($keys as $key) {
            $prefixedKeys[] = $this->getPrefixedKey($key);
        }

        if (empty($prefixedKeys)) {
            return true;
        }

        $result = $this->redis->del($prefixedKeys);

        return ((int) $result) > 0;
    }

    /**
     * @param string $key
     * @return bool
     */
    public function has(string $key): bool
    {
        $result = $this->redis->exists($this->getPrefixedKey($key));

        return ((int) $result) > 0;
    }

    /**
     * @param string $key
     * @return string
     */
    private function getPrefixedKey(string $key): string
    {
        return $this->prefix . $key;
    }

    /**
     * @param DateInterval $interval
     * @return int
     */
    private function dateIntervalToSeconds(DateInterval $interval): int
    {
        $reference = new DateTimeImmutable();
        $endTime = $reference->add($interval);

        return $endTime->getTimestamp() - $reference->getTimestamp();
    }
}
