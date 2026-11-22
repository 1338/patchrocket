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
            ? $this->authenticated($principal)
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

    public function accountPrincipal(Request $request): ?array
    {
        if (!$this->user($request)) {
            return null;
        }
        $principal = $request->getSession()->get(self::KEY)['principal'];

        return 'local' === $principal['type'] ? $principal : ($principal['account'] ?? null);
    }

    public function recent(Request $request): bool
    {
        return $this->recentRemaining($request) > 0;
    }

    public function recentRemaining(Request $request): int
    {
        if (!$this->user($request)) {
            return 0;
        }
        $record = $request->getSession()->get(self::KEY);

        return max(0, ($record['verified'] ?? $record['created']) + 900 - time());
    }

    public function confirmPassword(Request $request, #[\SensitiveParameter] string $password): void
    {
        $principal = $this->accountPrincipal($request);
        if (!$principal || $this->accounts->login($principal['subject'], $password) !== $principal) {
            throw new \DomainException('Enter the current account password.');
        }
        $session = $request->getSession();
        $session->set(self::KEY, array_replace($session->get(self::KEY), ['verified' => time()]));
    }

    public function updateAccount(Request $request, array $account): void
    {
        $principal = $request->getSession()->get(self::KEY)['principal'];
        if ('local' === $principal['type']) {
            $principal = $account;
        } else {
            $principal['account'] = $account;
        }
        $this->start($request, $principal);
    }

    public function signInPrincipal(array $provider, array $identity): ?array
    {
        if ($this->providers->blocked($provider, $identity)) {
            return null;
        }
        $link = $this->accounts->linked($provider, $identity['subject']);

        return null === $link
            ? ($this->providers->authenticated($identity) ? $identity : null)
            : $this->accounts->linkedPrincipal($link, $identity);
    }

    private function authenticated(array $principal): ?array
    {
        if ('local' === $principal['type']) {
            $user = $this->accounts->authenticated($principal);

            return $user ? $user + ['account' => $principal['subject']] : null;
        }
        $provider = $this->providers->get($principal['provider']);
        if (!$provider || $provider['version'] !== $principal['version']) {
            return null;
        }
        $link = $this->accounts->linked($provider, $principal['subject']);
        if (null === $link) {
            return isset($principal['account']) ? null : $this->providers->authenticated($principal);
        }
        if (!($link['enabled'] ?? false) || ($principal['method'] ?? null) !== $link['id']
            || ($principal['account']['subject'] ?? null) !== $link['account'] || $this->providers->blocked($provider, $principal)) {
            return null;
        }
        $user = $this->accounts->authenticated($principal['account']);

        return $user ? $user + ['account' => $link['account'], 'provider' => $provider['alias'], 'subject' => $principal['subject']] : null;
    }

    public function start(Request $request, array $principal): void
    {
        $session = $request->getSession();
        $session->invalidate();
        $session->set(self::KEY, ['principal' => $principal, 'created' => time(), 'active' => time(), 'verified' => time()]);
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
