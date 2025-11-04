<?php

namespace App\Security;

use App\Modules\AuditLogging\Entity\ActivityLog;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Psr\Log\LoggerInterface;
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
        $password = $request->request->get('password', '');
        $csrfToken = $request->request->get('_csrf_token');

        $request->getSession()->set(Security::LAST_USERNAME, $email);

        // Debug logs
        $this->logger->info('Authenticator: CSRF token from request: {token}', ['token' => $csrfToken]);
        $this->logger->info('Authenticator: session id {id}', ['id' => $request->getSession()->getId()]);

        return new Passport(
            new UserBadge($email),
            new PasswordCredentials($password),
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

        // Redirect to previously requested URL if present, otherwise to landing page
        $targetPath = $this->getTargetPath($request->getSession(), $firewallName);
        if ($targetPath) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('landing_page'));
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}


