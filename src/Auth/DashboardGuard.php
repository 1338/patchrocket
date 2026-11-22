<?php
declare(strict_types=1);

namespace App\Auth;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[AsEventListener(event: KernelEvents::REQUEST, priority: 16)]
final class DashboardGuard
{
    private const PUBLIC = ['auth_login', 'auth_setup', 'auth_sso_begin', 'auth_sso_callback'];

    public function __construct(
        private readonly DashboardAccounts $accounts,
        private readonly DashboardSession $session,
        private readonly UrlGeneratorInterface $router,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        if (!$event->isMainRequest() || !is_string($route) || in_array($route, self::PUBLIC, true)) {
            return;
        }
        $state = $this->accounts->state();
        $jsonAction = in_array($route, [
            'release_tracking', 'prepare', 'change_pull_request', 'verify_iac', 'vm_package_action', 'binary_update', 'binary_verify',
            'approve', 'change_independent_verification', 'change_retry_preparation',
        ], true);
        $api = str_starts_with($request->getPathInfo(), '/api/')
            || ($jsonAction && 'json' === $request->getPreferredFormat());
        $accountApi = 'api_queue' === $route || str_starts_with($route, 'api_profile') || str_starts_with($route, 'api_admin_users') || str_starts_with($route, 'api_kubernetes_') || str_starts_with($route, 'api_repository_');
        if (!$accountApi && !DashboardSession::needsAuthentication($request, $state)) {
            // Auth configuration still requires an authenticated administrator.
            if ('settings_access' !== $route && str_starts_with($route, 'settings_access')) {
                throw new AccessDeniedHttpException();
            }

            return;
        }
        $user = ($state['initialized'] ?? false) ? $this->session->user($request) : null;
        if (!$user) {
            $initialized = $state['initialized'] ?? false;
            $return = $initialized && !$api && $request->isMethod('GET') && '/' !== $request->getRequestUri()
                ? DashboardReturnPath::validate($request->getRequestUri()) : null;
            $login = $this->router->generate($initialized ? 'auth_login' : 'auth_setup', null === $return ? [] : ['return' => $return]);
            $event->setResponse($api
                ? new JsonResponse(['error' => 'Sign in to continue.', 'login' => $login], 401)
                : new RedirectResponse($login, 303));

            return;
        }
        $request->attributes->set('_dashboard_identity', $user['label']);
        $request->attributes->set('_dashboard_role', $user['role']);
        $request->attributes->set('_dashboard_actor', $user['account'] ?? $user['provider'].':'.$user['subject']);
        if (!$this->allowed($request, $route, $user['role'])) {
            if ($api) {
                $event->setResponse(new JsonResponse(['error' => 'Your dashboard role does not allow this action.'], 403));

                return;
            }
            throw new AccessDeniedHttpException('Your dashboard role does not allow this action.');
        }
    }

    private function allowed(Request $request, string $route, string $role): bool
    {
        if ('admin' === $role || 'auth_logout' === $route || 'auth_account' === $route || str_starts_with($route, 'api_profile')) {
            return true;
        }
        if (in_array($route, ['api_approval_tokens', 'api_pull_request_token'], true)
            || str_starts_with($route, 'settings') || str_starts_with($route, 'api_admin_users')
            || str_starts_with($route, 'api_kubernetes_') || str_starts_with($route, 'api_repository_')) {
            return false;
        }
        if (in_array($route, ['patch', 'binary_download', 'api_binary_build_token', 'api_binary_verify_token', 'api_finding_prepare_token',
            'api_retry_preparation_token', 'api_verify_iac_token', 'api_release_tracking_token'], true)) {
            return 'operator' === $role;
        }
        if ($request->isMethodSafe()) {
            return true;
        }

        return 'operator' === $role && (in_array($route, ['prepare', 'change_retry_preparation', 'release_tracking', 'binary_verify', 'verify_iac'], true)
            || ('binary_update' === $route && 'build' === $request->attributes->get('action')));
    }
}
