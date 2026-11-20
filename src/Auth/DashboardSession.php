<?php
declare(strict_types=1);

namespace App\Auth;

use Symfony\Component\HttpFoundation\Request;

final class DashboardSession
{
    private const KEY = 'patchrocket.session';
    private const LOCAL_HOSTS = '^localhost$,^127\.0\.0\.1$,^\[::1\]$';

    public function __construct(private readonly DashboardAccounts $accounts, private readonly IdentityProviders $providers)
    {
    }

    public function user(Request $request): ?array
    {
        if (!$request->hasPreviousSession()) {
            return null;
        }
        $session = $request->getSession();
        $record = $session->get(self::KEY);
        if (!$record) {
            return null;
        }
        $now = time();
        $principal = $record['principal'];
        $user = $record['created'] + 43200 > $now && $record['active'] + 3600 > $now
            ? ('local' === $principal['type'] ? $this->accounts->authenticated($principal) : $this->providers->authenticated($principal))
            : null;
        if (!$user) {
            $session->invalidate();

            return null;
        }
        if ($record['active'] + 60 <= $now) {
            $session->set(self::KEY, array_replace($record, ['active' => $now]));
        }

        return $user;
    }

    public function start(Request $request, array $principal): void
    {
        $session = $request->getSession();
        $session->invalidate();
        $session->set(self::KEY, ['principal' => $principal, 'created' => time(), 'active' => time()]);
    }

    public function end(Request $request): void
    {
        $request->getSession()->invalidate();
    }

    public static function needsAuthentication(Request $request, ?array $state): bool
    {
        return null !== $state || self::external($request);
    }

    public static function secureForSignIn(Request $request): bool
    {
        return $request->isSecure() || !self::external($request);
    }

    private static function external(Request $request): bool
    {
        return !in_array($request->getHost(), ['localhost', '127.0.0.1', '[::1]'], true)
            || '' !== trim($_SERVER['DASHBOARD_TRUSTED_PROXIES'] ?? '')
            || self::LOCAL_HOSTS !== ($_SERVER['DASHBOARD_TRUSTED_HOSTS'] ?? self::LOCAL_HOSTS)
            || $request->headers->has('Forwarded') || $request->headers->has('X-Forwarded-For')
            || $request->headers->has('X-Forwarded-Host') || $request->headers->has('X-Forwarded-Proto');
    }
}
