<?php

namespace QDenka\UltimateLinkChecker\Domain\Repository;

use QDenka\UltimateLinkChecker\Domain\Model\Link;

interface LinkRepositoryInterface
{
    public function save(Link $link): void;
    public function findByUrl(string $url): ?Link;
}
