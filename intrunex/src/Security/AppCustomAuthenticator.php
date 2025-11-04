<?php

namespace App\Security;

use App\Modules\AuditLogging\Entity\ActivityLog;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class AppCustomAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    private $csrfTokenManager;
    private $logger;

    public function __construct(private UrlGeneratorInterface $urlGenerator, private EntityManagerInterface $em, CsrfTokenManagerInterface $csrfTokenManager, LoggerInterface $logger)
    {
        $this->csrfTokenManager = $csrfTokenManager;
        $this->logger = $logger;
    }

    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email', '');

        $request->getSession()->set(Security::LAST_USERNAME, $email);

        $csrfToken = $request->request->get('_csrf_token');
        $sessionToken = $this->csrfTokenManager->getToken('authenticate')->getValue();

        $this->logger->info('CSRF token from request: {request_token}', ['request_token' => $csrfToken]);
        $this->logger->info('CSRF token from session: {session_token}', ['session_token' => $sessionToken]);
        $this->logger->info('Session ID: {session_id}', ['session_id' => $request->getSession()->getId()]);
        $this->logger->info('CSRF tokens match: {match}', ['match' => $this->csrfTokenManager->isTokenValid(new \Symfony\Component\Security\Csrf\CsrfToken('authenticate', $csrfToken))]);

        $session = $request->getSession();
        $this->logger->info('Authenticator: request method '.$request->getMethod());
        $this->logger->info('Authenticator: session id '.$session->getId());
        $reqToken = $request->request->get('_csrf_token');
        $this->logger->info('Authenticator: request CSRF token '.$reqToken);
        $stored = $this->csrfTokenManager->getToken('authenticate')->getValue();
        $this->logger->info('Authenticator: stored CSRF token '.$stored);

        if (!$this->csrfTokenManager->isTokenValid(new CsrfToken('authenticate', $reqToken))) {
            throw new InvalidCsrfTokenException();
        }

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($request->request->get('password', '')),
            [
                new CsrfTokenBadge('authenticate', $csrfToken),
                new RememberMeBadge(),
            ]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Log the login event
        $activityLog = new ActivityLog();
        $activityLog->setMessage('User logged in: ' . $token->getUser()->getUserIdentifier());
        $activityLog->setStatus('Success');
        $activityLog->setCreatedAt(new \DateTimeImmutable());
        $this->em->persist($activityLog);
        $this->em->flush();

        // Redirect to originally requested page if exists, else to dashboard
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('dashboard'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}


