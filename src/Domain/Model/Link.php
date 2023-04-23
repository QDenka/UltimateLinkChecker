<?php

namespace QDenka\UltimateLinkChecker\Domain\Model;

class Link
{
    private string $url;
    private bool $isBlocked = false;

    public function __construct(string $url)
    {
        $this->url = $url;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function isBlocked(): bool
    {
        return $this->isBlocked;
    }

    public function setBlocked(bool $isBlocked): void
    {
        $this->isBlocked = $isBlocked;
    }
}
