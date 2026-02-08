<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Result;

final class AggregateResult
{
    private bool $isSafe = true;

    /** @var array<string, CheckResult> */
    private array $providerResults = [];

    public function __construct(
        private readonly string $url
    ) {
    }

    /**
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * @param string $providerName
     * @param CheckResult $result
     * @return $this
     */
    public function addProviderResult(string $providerName, CheckResult $result): self
    {
        $this->providerResults[$providerName] = $result;

        return $this;
    }

    /**
     * @return array<string, CheckResult>
     */
    public function getProviderResults(): array
    {
        return $this->providerResults;
    }

    /**
     * @param string $providerName
     * @return CheckResult|null
     */
    public function getProviderResult(string $providerName): ?CheckResult
    {
        return $this->providerResults[$providerName] ?? null;
    }

    /**
     * Determine if the URL is safe based on the consensus method.
     *
     * - 'any': URL is unsafe if ANY provider flags it (strictest) => safe only if ALL providers say safe
     * - 'all': URL is unsafe only if ALL providers flag it (most lenient) => safe if at least one says safe
     * - 'majority': URL is unsafe if the MAJORITY of providers flag it => safe if majority says safe
     */
    public function determineOverallSafety(string $consensusMethod): bool
    {
        if (empty($this->providerResults)) {
            return true;
        }

        $unsafeCount = 0;
        $totalCount = count($this->providerResults);

        foreach ($this->providerResults as $result) {
            if (!$result->isSafe()) {
                $unsafeCount++;
            }
        }

        $this->isSafe = match ($consensusMethod) {
            'any' => $unsafeCount === 0,
            'all' => $unsafeCount < $totalCount,
            'majority' => $unsafeCount <= ($totalCount / 2),
            default => $unsafeCount === 0,
        };

        return $this->isSafe;
    }

    /**
     * @return bool
     */
    public function isSafe(): bool
    {
        return $this->isSafe;
    }

    /**
     * Get all threats reported by providers
     *
     * @return array<string, array<Threat>>
     */
    public function getThreats(): array
    {
        $threats = [];

        foreach ($this->providerResults as $providerName => $result) {
            if (!$result->isSafe()) {
                $threats[$providerName] = $result->getThreats();
            }
        }

        return $threats;
    }

    /**
     * Get a summary of all threats
     *
     * @return array<string, string>
     */
    public function getThreatSummary(): array
    {
        $summary = [];

        foreach ($this->providerResults as $providerName => $result) {
            if (!$result->isSafe()) {
                $threatTypes = array_map(
                    fn (Threat $threat) => $threat->getType(),
                    $result->getThreats()
                );

                $summary[$providerName] = implode(', ', array_unique($threatTypes));
            }
        }

        return $summary;
    }
}
