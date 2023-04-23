<?php

namespace QDenka\UltimateLinkChecker\Infrastructure\Persistence;

use QDenka\UltimateLinkChecker\Domain\Model\Link;
use QDenka\UltimateLinkChecker\Domain\Repository\LinkRepositoryInterface;

class LinkRepository implements LinkRepositoryInterface
{
    private array $links = [];

    public function save(Link $link): void
    {
        $this->links[$link->getUrl()] = $link;
    }

    public function findByUrl(string $url): ?Link
    {
        return $this->links[$url] ?? null;
    }
}
