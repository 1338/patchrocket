<?php
declare(strict_types=1);

namespace App\Controller;

use App\Auth\DashboardAccounts;
use App\Auth\DashboardSession;
use App\Auth\IdentityProviders;
use App\Auth\OAuthSignIn;
use App\Secrets\SecretManagers;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class AuthDashboard extends AbstractController
{
    private const FLOW = 'patchrocket.oauth';

    public function __construct(
        private readonly DashboardAccounts $accounts,
        private readonly DashboardSession $session,
        private readonly IdentityProviders $providers,
        private readonly OAuthSignIn $oauth,
        private readonly SecretManagers $secrets,
    ) {
    }

    #[Route('/setup', name: 'auth_setup', methods: ['GET', 'POST'])]
    public function setup(Request $request): Response
    {
        $this->requireSecureSignIn($request);
        $state = $this->accounts->state();
        if ($state['initialized'] ?? false) {
            return $this->redirectToRoute('auth_login');
        }
        $error = null;
        $status = Response::HTTP_OK;
        if ($request->isMethod('POST')) {
            $this->token($request, 'dashboard-setup');
            if (($state['expires'] ?? 0) <= time()) {
                $error = 'Generate a one-time setup code from the console.';
                $status = Response::HTTP_UNPROCESSABLE_ENTITY;
            } elseif (!$this->accounts->rateLimit($request->getClientIp() ?? 'unknown')) {
                $error = 'Too many attempts. Try again in five minutes.';
                $status = Response::HTTP_TOO_MANY_REQUESTS;
            } else {
                try {
                    $this->session->start($request, $this->accounts->setup(
                        $request->request->getString('username'), $request->request->getString('password'),
                        trim($request->request->getString('code')),
                    ));

                    return $this->redirectToRoute('settings_access', status: Response::HTTP_SEE_OTHER);
                } catch (\DomainException $problem) {
                    $error = $problem->getMessage();
                    $status = Response::HTTP_UNPROCESSABLE_ENTITY;
                }
            }
        }

        return $this->render('auth/login.html.twig', [
            'setup' => true, 'code_ready' => ($state['expires'] ?? 0) > time(), 'error' => $error,
        ], new Response(status: $status));
    }

    #[Route('/login', name: 'auth_login', methods: ['GET', 'POST'])]
    public function login(Request $request): Response
    {
        $this->requireSecureSignIn($request);
        if (!($this->accounts->state()['initialized'] ?? false)) {
            return $this->redirectToRoute('auth_setup');
        }
        if ($this->session->user($request)) {
            return $this->redirectToRoute('overview');
        }
        $error = null;
        $status = Response::HTTP_OK;
        if ($request->isMethod('POST')) {
            $this->token($request, 'dashboard-login');
            if (!$this->accounts->rateLimit($request->getClientIp() ?? 'unknown')) {
                $error = 'Too many attempts. Try again in five minutes.';
                $status = Response::HTTP_TOO_MANY_REQUESTS;
            } elseif ($principal = $this->accounts->login($request->request->getString('username'), $request->request->getString('password'))) {
                $this->session->start($request, $principal);

                return $this->redirectToRoute('overview', status: Response::HTTP_SEE_OTHER);
            } else {
                $error = 'The username or password is incorrect.';
                $status = Response::HTTP_UNAUTHORIZED;
            }
        }

        return $this->render('auth/login.html.twig', [
            'setup' => false, 'error' => $error, 'providers' => $this->providers->all(), 'types' => IdentityProviders::TYPES,
        ], new Response(status: $status));
    }

    #[Route('/login/{provider}/start', name: 'auth_sso_begin', requirements: ['provider' => '[a-z0-9][a-z0-9-]{0,31}'], methods: ['GET'])]
    public function begin(string $provider, Request $request): Response
    {
        $this->requireSecureSignIn($request);
        if (!($this->accounts->state()['initialized'] ?? false)) {
            return $this->redirectToRoute('auth_setup');
        }
        $configuration = $this->providers->get($provider) ?? throw $this->createNotFoundException();
        try {
            $callback = $this->generateUrl('auth_sso_callback', ['provider' => $provider], UrlGeneratorInterface::ABSOLUTE_URL);
            [$redirect, $flow] = $this->oauth->begin($configuration, $callback);
            $request->getSession()->set(self::FLOW, $flow);

            return new RedirectResponse($redirect);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('auth_login');
        }
    }

    #[Route('/login/{provider}/callback', name: 'auth_sso_callback', requirements: ['provider' => '[a-z0-9][a-z0-9-]{0,31}'], methods: ['GET'])]
    public function callback(string $provider, Request $request): Response
    {
        $this->requireSecureSignIn($request);
        if (!($this->accounts->state()['initialized'] ?? false)) {
            return $this->redirectToRoute('auth_setup');
        }
        $session = $request->getSession();
        $flow = $session->get(self::FLOW);
        $configuration = $this->providers->get($provider);
        try {
            if (!$flow || !$configuration || $flow['expires'] <= time() || $flow['alias'] !== $provider
                || $flow['version'] !== $configuration['version'] || !hash_equals($flow['state'], $request->query->getString('state'))) {
                throw new \DomainException('The sign-in request is invalid or expired. Start again from the login page.');
            }
            $session->remove(self::FLOW);
            if ($request->query->has('error')) {
                throw new \DomainException('Sign-in was declined by the identity provider.');
            }
            $principal = $this->oauth->finish($configuration, $flow, $request->query->getString('code'));
            if (!$this->providers->authenticated($principal)) {
                throw new \DomainException('Your provider account has no dashboard role. Give your administrator this subject ID: '.$principal['subject']);
            }
            $this->session->start($request, $principal);

            return $this->redirectToRoute('overview', status: Response::HTTP_SEE_OTHER);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('auth_login', status: Response::HTTP_SEE_OTHER);
        }
    }

    #[Route('/logout', name: 'auth_logout', methods: ['POST'])]
    public function logout(Request $request): Response
    {
        $this->token($request, 'dashboard-logout');
        $this->session->end($request);

        return $this->redirectToRoute('auth_login', status: Response::HTTP_SEE_OTHER);
    }

    #[Route('/account', name: 'auth_account', methods: ['GET'])]
    public function account(Request $request): Response
    {
        $user = $this->session->user($request) ?? throw $this->createNotFoundException();

        return $this->render('auth/account.html.twig', ['user' => $user, 'roles' => DashboardAccounts::ROLES]);
    }

    #[Route('/settings/access', name: 'settings_access', methods: ['GET'])]
    public function access(Request $request): Response
    {
        $enabled = $this->accounts->state()['initialized'] ?? false;
        $accounts = $enabled ? array_column($this->accounts->all(), null, 'username') : [];
        $providers = $enabled ? array_column($this->providers->all(), null, 'alias') : [];

        return $this->render('auth/access.html.twig', [
            'access_view' => $request->query->getString('add'),
            'provider_type' => isset(IdentityProviders::TYPES[$request->query->getString('type')]) ? $request->query->getString('type') : null,
            'enabled' => $enabled, 'accounts' => $accounts, 'providers' => $providers, 'types' => IdentityProviders::TYPES,
            'editing_account' => $accounts[$request->query->getString('account')] ?? null,
            'editing_provider' => $providers[$request->query->getString('provider')] ?? null,
            'roles' => DashboardAccounts::ROLES, 'vault_destinations' => $enabled ? $this->secrets->vaultDestinations() : [],
        ]);
    }

    #[Route('/settings/access/{action}', name: 'settings_access_edit', requirements: ['action' => 'account|account-remove|provider|provider-remove'], methods: ['POST'])]
    public function edit(string $action, Request $request): Response
    {
        $this->token($request, 'dashboard-access-'.$action);
        $fields = $request->request;
        try {
            match ($action) {
                'account' => $this->accounts->save($fields->getString('username'), $fields->getString('password'), $fields->getString('role')),
                'account-remove' => $this->accounts->remove($fields->getString('username')),
                'provider' => $this->providers->save(array_filter($fields->all(), is_string(...))),
                'provider-remove' => $this->providers->remove($fields->getString('alias')),
            };
            $this->addFlash('success', 'Access settings saved.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        } catch (\RuntimeException) {
            $this->addFlash('error', 'Access settings could not be saved.');
        }

        return $this->redirectToRoute('settings_access', status: Response::HTTP_SEE_OTHER);
    }

    private function token(Request $request, string $id): void
    {
        if (!$this->isCsrfTokenValid($id, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
    }

    private function requireSecureSignIn(Request $request): void
    {
        if (!DashboardSession::secureForSignIn($request)) {
            throw $this->createAccessDeniedException('Use the dashboard’s HTTPS URL to sign in.');
        }
    }
}
