<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AnalyticsController extends AbstractController
{
    #[Route('/analytics', name: 'app_analytics')]
    public function index(): Response
    {
        // Dummy data for demonstration
        $totalAssets = 120;
        $totalScans = 350;
        $vulnerabilitiesFound = 850;
        $criticalIssues = 75;

        $severityData = [
            'Critical' => 75,
            'High' => 200,
            'Medium' => 350,
            'Low' => 225,
        ];

        $vulnerabilityTrendData = [
            'labels' => ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
            'data' => [50, 60, 75, 80, 90, 100, 110, 105, 120, 130, 140, 150],
        ];

        $recentScans = [
            ['asset' => 'Server A', 'date' => '2025-11-01', 'vulnerabilities' => 15, 'severity' => 'High'],
            ['asset' => 'Workstation B', 'date' => '2025-10-28', 'vulnerabilities' => 5, 'severity' => 'Low'],
            ['asset' => 'Web App C', 'date' => '2025-10-25', 'vulnerabilities' => 22, 'severity' => 'Critical'],
            ['asset' => 'Database D', 'date' => '2025-10-20', 'vulnerabilities' => 8, 'severity' => 'Medium'],
        ];

        return $this->render('analytics/index.html.twig', [
            'totalAssets' => $totalAssets,
            'totalScans' => $totalScans,
            'vulnerabilitiesFound' => $vulnerabilitiesFound,
            'criticalIssues' => $criticalIssues,
            'severityData' => $severityData,
            'vulnerabilityTrendData' => $vulnerabilityTrendData,
            'recentScans' => $recentScans,
        ]);
    }
}
