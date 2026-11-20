<?php
declare(strict_types=1);

namespace App\Auth;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
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
        if (!DashboardSession::needsAuthentication($request, $state)) {
            // Auth configuration still requires an authenticated administrator.
            if ('settings_access' !== $route && str_starts_with($route, 'settings_access')) {
                throw new AccessDeniedHttpException();
            }

            return;
        }
        $user = ($state['initialized'] ?? false) ? $this->session->user($request) : null;
        if (!$user) {
            $event->setResponse(new RedirectResponse($this->router->generate(($state['initialized'] ?? false) ? 'auth_login' : 'auth_setup'), 303));

            return;
        }
        $request->attributes->set('_dashboard_identity', $user['label']);
        $request->attributes->set('_dashboard_role', $user['role']);
        if (!$this->allowed($request, $route, $user['role'])) {
            throw new AccessDeniedHttpException('Your dashboard role does not allow this action.');
        }
    }

    private function allowed(Request $request, string $route, string $role): bool
    {
        if ('admin' === $role || 'auth_logout' === $route || 'auth_account' === $route) {
            return true;
        }
        if (str_starts_with($route, 'settings')) {
            return false;
        }
        if (in_array($route, ['patch', 'binary_download'], true)) {
            return 'operator' === $role;
        }
        if ($request->isMethodSafe()) {
            return true;
        }

        return 'operator' === $role && (in_array($route, ['prepare', 'release_tracking', 'binary_verify', 'verify_iac'], true)
            || ('binary_update' === $route && 'build' === $request->attributes->get('action')));
    }
}
