<?php
declare(strict_types=1);

namespace App\Controller;

use App\Auth\DashboardAccounts;
use App\Auth\DashboardReturnPath;
use App\Auth\DashboardSession;
use App\Auth\IdentityProviders;
use App\Auth\OAuthSignIn;
use App\Secrets\SecretManagers;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Exception\JsonException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class AuthDashboard extends AbstractController
{
    private const FLOW = 'patchrocket.oauth';
    public const PROVIDER_EDIT_CSRF = 'dashboard-access-provider';

    public function __construct(
        private readonly DashboardAccounts $accounts,
        private readonly DashboardSession $session,
        private readonly IdentityProviders $providers,
        private readonly OAuthSignIn $oauth,
        private readonly SecretManagers $secrets,
        private readonly PreactPage $preact,
        private readonly \Symfony\Component\Security\Csrf\CsrfTokenManagerInterface $tokens,
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
        $username = 'admin';
        $status = Response::HTTP_OK;
        if ($request->isMethod('POST')) {
            $this->token($request, 'dashboard-setup');
            $username = $request->request->getString('username');
            if (($state['expires'] ?? 0) <= time()) {
                $error = 'Generate a one-time setup code from the console.';
                $status = Response::HTTP_UNPROCESSABLE_ENTITY;
            } elseif (!$this->accounts->rateLimit($request->getClientIp() ?? 'unknown')) {
                $error = 'Too many attempts. Try again in five minutes.';
                $status = Response::HTTP_TOO_MANY_REQUESTS;
            } else {
                try {
                    $this->session->start($request, $this->accounts->setup(
                        $username, $request->request->getString('password'),
                        trim($request->request->getString('code')),
                    ));

                    return $this->redirectToRoute('settings_getting-started', status: Response::HTTP_SEE_OTHER);
                } catch (\DomainException $problem) {
                    $error = $problem->getMessage();
                    $status = Response::HTTP_UNPROCESSABLE_ENTITY;
                }
            }
        }

        return $this->preact->render('setup', [
            'code_ready' => ($state['expires'] ?? 0) > time(), 'error' => $error, 'username' => substr($username, 0, 40),
        ], $this->formTokens(['setup' => 'dashboard-setup']), $status);
    }

    #[Route('/login', name: 'auth_login', methods: ['GET', 'POST'])]
    public function login(Request $request): Response
    {
        $this->requireSecureSignIn($request);
        if (!($this->accounts->state()['initialized'] ?? false)) {
            return $this->redirectToRoute('auth_setup');
        }
        $return = DashboardReturnPath::validate(($request->isMethod('POST') ? $request->request : $request->query)->all()['return'] ?? null);
        if ($this->session->user($request)) {
            return $this->afterSignIn($return);
        }
        $error = null;
        $username = '';
        $status = Response::HTTP_OK;
        if ($request->isMethod('POST')) {
            $this->token($request, 'dashboard-login');
            $username = $request->request->getString('username');
            if (!$this->accounts->rateLimit($request->getClientIp() ?? 'unknown')) {
                $error = 'Too many attempts. Try again in five minutes.';
                $status = Response::HTTP_TOO_MANY_REQUESTS;
            } elseif ($principal = $this->accounts->login($username, $request->request->getString('password'))) {
                $this->session->start($request, $principal);

                return $this->afterSignIn($return);
            } else {
                $error = 'The username or password is incorrect.';
                $status = Response::HTTP_UNAUTHORIZED;
            }
        }

        $providers = array_map(fn (array $provider): array => [
            'alias' => $provider['alias'], 'label' => IdentityProviders::TYPES[$provider['type']],
            'url' => $this->generateUrl('auth_sso_begin', ['provider' => $provider['alias']] + $this->returnQuery($return)),
        ], $this->providers->all());

        return $this->preact->render('login', [
            'error' => $error, 'providers' => $providers, 'return' => $return, 'username' => substr($username, 0, 40),
        ],
            $this->formTokens(['login' => 'dashboard-login']), $status);
    }

    #[Route('/login/{provider}/start', name: 'auth_sso_begin', requirements: ['provider' => '[a-z0-9][a-z0-9-]{0,31}'], methods: ['GET'])]
    public function begin(string $provider, Request $request): Response
    {
        $this->requireSecureSignIn($request);
        if (!($this->accounts->state()['initialized'] ?? false)) {
            return $this->redirectToRoute('auth_setup');
        }
        $configuration = $this->providers->get($provider) ?? throw $this->createNotFoundException();
        $return = DashboardReturnPath::validate($request->query->all()['return'] ?? null);
        try {
            $callback = $this->generateUrl('auth_sso_callback', ['provider' => $provider], UrlGeneratorInterface::ABSOLUTE_URL);
            [$redirect, $flow] = $this->oauth->begin($configuration, $callback);
            $request->getSession()->set(self::FLOW, $flow + $this->returnQuery($return));

            return new RedirectResponse($redirect);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('auth_login', $this->returnQuery($return));
        }
    }

    #[Route('/api/profile/link', name: 'api_profile_link', methods: ['POST'])]
    public function beginLink(Request $request): JsonResponse
    {
        $this->requireSecureSignIn($request);
        if (!$this->isCsrfTokenValid(AccountApi::PROFILE_CSRF, $request->headers->get('X-CSRF-Token', ''))) {
            return $this->json(['error' => 'Your profile session expired. Reload and try again.', 'code' => 'csrf_expired'], 403);
        }
        $account = $this->session->accountPrincipal($request);
        if (!$account) {
            return $this->json(['error' => 'Sign in to your PatchRocket account again before linking a method.'], 403);
        }
        try {
            $payload = $request->toArray();
            if (array_key_exists('account', $payload) && $payload['account'] !== $account['subject']) {
                return $this->json(['error' => AccountApi::PROFILE_ACCOUNT_CHANGED], 409);
            }
            if (!$this->session->recent($request)) {
                return $this->json(AccountApi::PROFILE_CONFIRMATION_REQUIRED, 403);
            }
            $alias = $payload['provider'] ?? null;
            $configuration = is_string($alias) ? $this->providers->get($alias) : null;
            if (!$configuration) {
                return $this->json(['error' => 'Choose an enabled identity provider.'], 422);
            }
            $callback = $this->generateUrl('auth_sso_callback', ['provider' => $alias], UrlGeneratorInterface::ABSOLUTE_URL);
            [$redirect, $flow] = $this->oauth->begin($configuration, $callback, link: true);
            $request->getSession()->set(self::FLOW, $flow + ['link' => $account]);

            return $this->json(['redirect' => $redirect]);
        } catch (JsonException) {
            return $this->json(['error' => 'Send a JSON object.'], 400);
        } catch (\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], 422);
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
            $identity = $this->oauth->finish($configuration, $flow, $request->query->getString('code'));
            $current = $this->providers->get($provider);
            if (!$current || $current['version'] !== $configuration['version']) {
                throw new \DomainException('The identity provider changed. Start the sign-in again.');
            }
            if (isset($flow['link'])) {
                $account = $this->session->accountPrincipal($request);
                if ($account !== $flow['link'] || !$this->session->recent($request) || $this->providers->blocked($configuration, $identity)) {
                    throw new \DomainException('The sign-in method could not be linked. Sign in to your account again and check provider access.');
                }
                $this->session->updateAccount($request, $this->accounts->link($account, $configuration, $identity));
                $this->addFlash('success', 'Sign-in method linked.');

                return new RedirectResponse('/app/profile', Response::HTTP_SEE_OTHER);
            }
            $principal = $this->session->signInPrincipal($configuration, $identity);
            if (!$principal) {
                throw new \DomainException('Your provider account has no dashboard access. Give your administrator this subject ID: '.$identity['subject']);
            }
            $this->session->start($request, $principal);

            return $this->afterSignIn($flow['return'] ?? null);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            if (isset($flow['link'])) {
                return new RedirectResponse('/app/profile', Response::HTTP_SEE_OTHER);
            }

            return $this->redirectToRoute('auth_login', $this->returnQuery($flow['return'] ?? null), Response::HTTP_SEE_OTHER);
        }
    }

    private function afterSignIn(?string $return): RedirectResponse
    {
        return new RedirectResponse($return ?? $this->generateUrl('overview'), Response::HTTP_SEE_OTHER);
    }

    private function returnQuery(?string $return): array
    {
        return null === $return ? [] : ['return' => $return];
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

        return $this->preact->render('profile');
    }

    #[Route('/settings/access', name: 'settings_access', methods: ['GET'])]
    public function access(Request $request): Response
    {
        $enabled = $this->accounts->state()['initialized'] ?? false;
        $accounts = $enabled ? array_column($this->accounts->all(), null, 'username') : [];
        $providers = $enabled ? array_column($this->providers->all(), null, 'alias') : [];

        foreach ($providers as &$provider) {
            $provider['callback'] = $this->generateUrl('auth_sso_callback', ['provider' => $provider['alias']], UrlGeneratorInterface::ABSOLUTE_URL);
        }
        unset($provider);

        return $this->preact->render('settings-access', [
            'access_view' => $request->query->getString('add'),
            'provider_type' => isset(IdentityProviders::TYPES[$request->query->getString('type')]) ? $request->query->getString('type') : null,
            'enabled' => $enabled, 'accounts' => $accounts, 'providers' => $providers, 'types' => IdentityProviders::TYPES,
            'editing_account' => $accounts[$request->query->getString('account')] ?? null,
            'editing_provider' => $providers[$request->query->getString('provider')] ?? null,
            'callback_template' => $this->generateUrl('auth_sso_callback', ['provider' => 'callback-alias'], UrlGeneratorInterface::ABSOLUTE_URL),
            'roles' => DashboardAccounts::ROLES, 'vault_destinations' => $enabled ? $this->secrets->vaultDestinations() : [],
        ], $enabled ? $this->formTokens([
            'account' => 'dashboard-access-account', 'account-remove' => 'dashboard-access-account-remove',
            'provider' => self::PROVIDER_EDIT_CSRF, 'provider-remove' => 'dashboard-access-provider-remove',
            'store-credential' => 'settings-store-credential',
        ]) : []);
    }

    #[Route('/settings/access/{action}', name: 'settings_access_edit', requirements: ['action' => 'account|account-remove|provider|provider-remove'], methods: ['POST'])]
    #[Route('/api/settings/access/provider', name: 'settings_access_provider_api', defaults: ['action' => 'provider'], methods: ['POST'])]
    public function edit(string $action, Request $request): Response
    {
        $fields = $request->request;
        $json = 'settings_access_provider_api' === $request->attributes->get('_route');
        $headers = ['Cache-Control' => 'private, no-store'];
        $purpose = 'provider' === $action ? self::PROVIDER_EDIT_CSRF : 'dashboard-access-'.$action;
        if (!$this->isCsrfTokenValid($purpose, $fields->getString('_token'))) {
            if ($json) {
                return $this->json(['error' => 'Your settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'],
                    Response::HTTP_FORBIDDEN, $headers);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }
        try {
            match ($action) {
                'account' => $this->accounts->save($fields->getString('username'), $fields->getString('password'), $fields->getString('role'), actor: $request->attributes->get('_dashboard_actor')),
                'account-remove' => $this->accounts->remove($fields->getString('username'), $request->attributes->get('_dashboard_actor')),
                'provider' => $this->providers->save(array_filter($fields->all(), is_string(...))),
                'provider-remove' => $this->providers->remove($fields->getString('alias')),
            };
            $this->addFlash('success', 'provider' === $action ? 'Identity provider saved.' : 'Access settings saved.');
        } catch (\DomainException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        } catch (\RuntimeException) {
            if ($json) {
                return $this->json(['error' => 'Access settings could not be saved.'], Response::HTTP_INTERNAL_SERVER_ERROR, $headers);
            }
            $this->addFlash('error', 'Access settings could not be saved.');
        }

        if ($json) {
            return $this->json(['redirect' => $this->generateUrl('settings_access', ['_fragment' => 'identity-providers'])], headers: $headers);
        }

        return $this->redirectToRoute('settings_access', status: Response::HTTP_SEE_OTHER);
    }

    private function formTokens(array $purposes): array
    {
        return array_map(fn (string $purpose): string => $this->tokens->getToken($purpose)->getValue(), $purposes);
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
