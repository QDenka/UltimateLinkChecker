<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Contract;

use Qdenka\UltimateLinkChecker\Result\CheckResult;

interface ProviderInterface
{
    /**
     * Get the name of the provider
     */
    public function getName(): string;

    /**
     * Check a single URL
     */
    public function check(string $url): CheckResult;

    /**
     * Check multiple URLs at once
     *
     * @param array<string> $urls
     * @return array<string, CheckResult>
     */
    public function checkBatch(array $urls): array;
}
