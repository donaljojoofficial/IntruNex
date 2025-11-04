<?php

namespace App\Modules\LandingAndInfo\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpFoundation\RedirectResponse;

class SecurityController extends AbstractController
{
    // allow POST on the same route so the AbstractLoginFormAuthenticator can detect and intercept it
    #[Route(path: '/login', name: 'app_login', methods: ['GET','POST'])]
    public function login(Request $request, AuthenticationUtils $authenticationUtils, LoggerInterface $logger, CsrfTokenManagerInterface $csrfManager): Response
    {
        $session = $request->getSession();
        $logger->info('Login action start (method): '.$request->getMethod());
        $logger->info('Session ID at entry: '.$session->getId());

        if ($request->isMethod('POST')) {
            $requestToken = $request->request->get('_csrf_token');
            $logger->info('Request CSRF token: '.$requestToken);
            // Try to read token from manager for same id to show stored value (debug only)
            $stored = $csrfManager->getToken('authenticate')->getValue();
            $logger->info('CsrfTokenManager stored token for "authenticate": '.$stored);
        } else {
            // on GET show what token will be rendered
            $renderToken = $csrfManager->getToken('authenticate')->getValue();
            $logger->info('CsrfTokenManager token for "authenticate" at render: '.$renderToken);
        }

        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
