<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Result;

final class CheckResult
{
    /** @var array<Threat> */
    private array $threats = [];

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
     * @param Threat $threat
     * @return $this
     */
    public function addThreat(string $providerName, Threat $threat): self
    {
        $threat->setProviderName($providerName);
        $this->threats[] = $threat;

        return $this;
    }

    /**
     * @return array<Threat>
     */
    public function getThreats(): array
    {
        return $this->threats;
    }

    /**
     * @return bool
     */
    public function isSafe(): bool
    {
        return empty($this->threats);
    }

    /**
     * Get unique threat types from all threats
     *
     * @return array<string>
     */
    public function getThreatTypes(): array
    {
        return array_unique(
            array_map(
                fn (Threat $threat) => $threat->getType(),
                $this->threats
            )
        );
    }

    /**
     * Get the first threat type or null if no threats
     *
     * @return string|null
     */
    public function getThreatType(): ?string
    {
        if (empty($this->threats)) {
            return null;
        }

        return $this->threats[0]->getType();
    }

    /**
     * Check if the result contains a specific threat type
     *
     * @param string $threatType
     * @return bool
     */
    public function hasThreatType(string $threatType): bool
    {
        foreach ($this->threats as $threat) {
            if ($threat->getType() === $threatType) {
                return true;
            }
        }

        return false;
    }
}
