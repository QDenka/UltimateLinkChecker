<?php

namespace QDenka\UltimateLinkChecker\Domain\Service;

use QDenka\UltimateLinkChecker\Domain\Model\Link;

interface LinkCheckerServiceInterface
{
    public function checkLink(Link $link): void;
}
