<?php

namespace App\Modules\ScanManagement\Service;

use App\Modules\AssetDiscovery\Entity\Asset;
use App\Modules\ScanManagement\Entity\ScanJob;
use Doctrine\ORM\EntityManagerInterface;

class ScanJobService
{
    private EntityManagerInterface $em;

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    public function fetchAsset(int $assetId): ?Asset
    {
        return $this->em->getRepository(Asset::class)->find($assetId);
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
