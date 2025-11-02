<?php

namespace App\Modules\AuditLogging\Controller;

use App\Modules\AuditLogging\Entity\ActivityLog;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ActivityLogController extends AbstractController
{
    #[Route('/activity-log', name: 'activity_log')]
    #[IsGranted('ROLE_ADMIN')]
    public function index(EntityManagerInterface $em): Response
    {
        $activityLogs = $em->getRepository(ActivityLog::class)->findBy([], ['createdAt' => 'DESC']);

        return $this->render('audit_logging/activity_log/index.html.twig', [
            'activity_logs' => $activityLogs,
        ]);
    }
}
