<?php

namespace App\Modules\Reporting\Controller;

use App\Modules\AssetVulnerability\Entity\Vulnerability;
use App\Modules\ScanManagement\Entity\ScanJob;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ReportController extends AbstractController
{
    #[Route('/report/{id}', name: 'report_view')]
    public function viewReport($id, EntityManagerInterface $em): Response
    {
        $scanJob = $em->getRepository(ScanJob::class)->find($id);

        if (!$scanJob || $scanJob->getAsset()->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        $asset = $scanJob->getAsset();
        $vulnerabilities = $em->getRepository(Vulnerability::class)->findBy(['asset' => $asset]);

        return $this->render('reporting/report/view.html.twig', [
            'scanJob' => $scanJob,
            'asset' => $asset,
            'vulnerabilities' => $vulnerabilities,
        ]);
    }
}
