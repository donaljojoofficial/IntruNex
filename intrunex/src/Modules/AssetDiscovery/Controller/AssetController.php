<?php

namespace App\Modules\AssetDiscovery\Controller;

use App\Modules\AssetDiscovery\Entity\Asset;
use App\Modules\AssetVulnerability\Entity\Vulnerability;
use App\Modules\AssetDiscovery\Form\AssetFormType;
use App\Modules\AssetDiscovery\Service\AssetProfilingService;
use App\Modules\VulnerabilityDetection\Service\VulnerabilityScanService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/assets')]
class AssetController extends AbstractController
{
    private AssetProfilingService $assetProfilingService;
    private VulnerabilityScanService $vulnerabilityScanService;

    public function __construct(
        AssetProfilingService $assetProfilingService,
        VulnerabilityScanService $vulnerabilityScanService
    ) {
        $this->assetProfilingService = $assetProfilingService;
        $this->vulnerabilityScanService = $vulnerabilityScanService;
    }

    #[Route('/', name: 'asset_list')]
    public function list(EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $assets = $em->getRepository(Asset::class)
                     ->findBy(['user' => $this->getUser()], ['userAssetNumber' => 'ASC']);

        return $this->render('asset_discovery/asset/list.html.twig', [
            'assets' => $assets,
        ]);
    }

    #[Route('/create', name: 'asset_create')]
    public function create(Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $asset = new Asset();
        $form = $this->createForm(AssetFormType::class, $asset);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $asset->setUser($this->getUser());

            // Assign next userAssetNumber
            $qb = $em->createQueryBuilder();
            $qb->select('MAX(a.userAssetNumber)')
               ->from(Asset::class, 'a')
               ->where('a.user = :user')
               ->setParameter('user', $this->getUser());
            $maxNum = (int)$qb->getQuery()->getSingleScalarResult();
            $asset->setUserAssetNumber($maxNum + 1);

            $em->persist($asset);
            $em->flush();

            try {
                $this->assetProfilingService->profile($asset);
                $this->addFlash('success', 'Asset created and profiling started.');
            } catch (\Exception $e) {
                $this->addFlash('error', 'Asset created but profiling failed: '.$e->getMessage());
            }

            return $this->redirectToRoute('asset_list');
        }

        return $this->render('asset_discovery/asset/create.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    #[Route('/{id}/edit', name: 'asset_edit')]
    public function edit($id, Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $asset = $em->getRepository(Asset::class)->find($id);

        if (!$asset || $asset->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        $form = $this->createForm(AssetFormType::class, $asset);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $em->flush();
            $this->addFlash('success', 'Asset updated successfully.');
            return $this->redirectToRoute('asset_list');
        }

        return $this->render('asset_discovery/asset/edit.html.twig', [
            'form' => $form->createView(),
            'asset' => $asset,
        ]);
    }

    #[Route('/{id}/delete', name: 'asset_delete', methods: ['POST'])]
    public function delete($id, Request $request, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $asset = $em->getRepository(Asset::class)->find($id);
        if (!$asset || $asset->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        if ($this->isCsrfTokenValid('delete-asset'.$asset->getId(), $request->request->get('_token'))) {
            $user = $asset->getUser();

            $em->remove($asset);
            $em->flush();

            // Reindex
            $assets = $em->getRepository(Asset::class)
                         ->findBy(['user' => $user], ['userAssetNumber' => 'ASC']);
            $i = 1;
            foreach ($assets as $a) {
                $a->setUserAssetNumber($i++);
                $em->persist($a);
            }
            $em->flush();

            $this->addFlash('success', 'Asset deleted.');
        } else {
            $this->addFlash('error', 'Invalid CSRF token.');
        }

        return $this->redirectToRoute('asset_list');
    }

    #[Route('/{id}', name: 'asset_detail', methods: ['GET'])]
    public function detail($id, EntityManagerInterface $em): Response
    {
        $asset = $em->getRepository(Asset::class)->find($id);

        if (!$asset || $asset->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        $vulnerabilities = $em->getRepository(Vulnerability::class)->findBy(['asset' => $asset]);

        return $this->render('asset_discovery/asset/detail.html.twig', [
            'asset' => $asset,
            'vulnerabilities' => $vulnerabilities,
        ]);
    }

    #[Route('/{id}/profile', name: 'asset_profile', methods: ['POST'])]
    public function profileAsset($id, Request $request, AssetProfilingService $profilingService, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');

        $asset = $em->getRepository(Asset::class)->find($id);

        if (!$asset || $asset->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        if ($this->isCsrfTokenValid('profile-asset'.$asset->getId(), $request->request->get('_token'))) {
            $profilingService->profile($asset);
            $this->addFlash('success', 'Asset profiling started.');
        } else {
            $this->addFlash('error', 'Invalid CSRF token.');
        }

        return $this->redirectToRoute('asset_detail', ['id' => $asset->getId()]);
    }

    #[Route('/vuln-scan/{id}', name: 'asset_vuln_scan', methods: ['POST'])]
    public function vulnScan($id, Request $request, VulnerabilityScanService $vulnerabilityScanService, MessageBusInterface $bus, EntityManagerInterface $em): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');
        $asset = $em->getRepository(Asset::class)->find($id);

        if (!$asset || $asset->getUser() !== $this->getUser()) {
            throw $this->createNotFoundException();
        }

        if ($this->isCsrfTokenValid('vuln-scan-asset'.$asset->getId(), $request->request->get('_token'))) {
            try {
                $scanJob = $vulnerabilityScanService->scanAsset($asset);
                $this->addFlash('success', 'Vulnerability scan started for asset: ' . $asset->getName());
                return $this->redirectToRoute('vulnerability_scan_progress', ['id' => $scanJob->getId()]);
            } catch (\Exception $e) {
                $this->addFlash('error', 'Failed to start vulnerability scan: ' . $e->getMessage());
            }
        } else {
            $this->addFlash('error', 'Invalid CSRF token.');
        }

        return $this->redirectToRoute('dashboard');
    }
}
