<?php

namespace QDenka\UltimateLinkChecker\Application\Service;

use QDenka\UltimateLinkChecker\Domain\Model\Link;
use QDenka\UltimateLinkChecker\Domain\Repository\LinkRepositoryInterface;
use QDenka\UltimateLinkChecker\Domain\Service\LinkCheckerServiceInterface;

class CheckLinkService implements LinkCheckerServiceInterface
{
    private LinkRepositoryInterface $linkRepository;
    private array $linkCheckerServices;

    public function __construct(LinkRepositoryInterface $linkRepository, array $linkCheckerServices)
    {
        $this->linkRepository = $linkRepository;
        $this->linkCheckerServices = $linkCheckerServices;
    }

    public function checkLink(Link $link): void
    {
        $existingLink = $this->linkRepository->findByUrl($link->getUrl());
        if ($existingLink !== null) {
            $link = $existingLink;
        }

        // Проверяем ссылку на блокировку с помощью всех сервисов
        foreach ($this->linkCheckerServices as $linkCheckerService) {
            $linkCheckerService->checkLink($link);
        }

        // Сохраняем результат проверки
        $this->linkRepository->save($link);
    }
}
