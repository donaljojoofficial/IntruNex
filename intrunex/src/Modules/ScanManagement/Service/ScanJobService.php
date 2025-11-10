<?php

namespace App\Modules\ScanManagement\Service;

use App\Modules\AssetDiscovery\Entity\Asset;
use App\Modules\AssetDiscovery\Repository\AssetRepository;
use App\Modules\ScanManagement\Entity\ScanJob;
use Doctrine\ORM\EntityManagerInterface;

class ScanJobService
{
    private EntityManagerInterface $em;
    private AssetRepository $assetRepository;

    public function __construct(EntityManagerInterface $em, AssetRepository $assetRepository)
    {
        $this->em = $em;
        $this->assetRepository = $assetRepository;
    }

    public function fetchAsset(int $assetId): ?Asset
    {
        return $this->assetRepository->findForCurrentUser($assetId);
    }

    public function createScanJob(Asset $asset): ScanJob
    {
        $scanJob = new ScanJob();
        $scanJob->setAsset($asset);
        $scanJob->setStatus('running');
        $scanJob->setStartedAt(new \DateTimeImmutable());

        $this->em->persist($scanJob);
        $this->em->flush();

        return $scanJob;
    }
}
