<?php

namespace App\Modules\Reporting\Controller;

use App\Modules\ScanManagement\Repository\ScanJobRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ScanReportController extends AbstractController
{
    #[Route('/reporting/scan-reports', name: 'scan_reports_index')]
    public function index(ScanJobRepository $scanJobRepository): Response
    {
        $scanJobs = $scanJobRepository->findAll();

        return $this->render('reporting/scan_report/index.html.twig', [
            'controller_name' => 'ScanReportController',
            'scanJobs' => $scanJobs,
        ]);
    }
}
