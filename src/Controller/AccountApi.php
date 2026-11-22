<?php
declare(strict_types=1);

namespace App\Controller;

use App\Auth\DashboardAccounts;
use App\Auth\DashboardSession;
use App\Auth\IdentityProviders;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Exception\JsonException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class AccountApi extends AbstractController
{
    public const USERS_CSRF = 'dashboard-users';
    public const PROFILE_CSRF = 'dashboard-profile';
    public const PROFILE_ACCOUNT_CHANGED = 'The signed-in account changed. Sign out in a separate tab and sign back in to the account shown on this form before retrying.';
    public const PROFILE_CONFIRMATION_REQUIRED = [
        'error' => 'Confirm your current account password before continuing.',
        'code' => 'profile_confirmation_required',
    ];

    public function __construct(
        private readonly DashboardAccounts $accounts,
        private readonly DashboardSession $session,
        private readonly IdentityProviders $providers,
        private readonly CsrfTokenManagerInterface $csrf,
    ) {
    }

    #[Route('/api/profile', name: 'api_profile', methods: ['GET'])]
    public function profile(Request $request): JsonResponse
    {
        $user = $this->session->user($request) ?? throw $this->createAccessDeniedException();
        $account = $user['account'] ?? null;
        $methods = null === $account ? [[
            'id' => $user['provider'], 'type' => 'provider', 'label' => $user['provider'],
            'provider' => $user['provider'], 'subject' => $user['subject'],
        ]] : $this->accounts->methods($account);
        $providers = null === $account ? [] : array_map(
            static fn (array $provider): array => ['alias' => $provider['alias'], 'label' => $provider['alias']],
            $this->providers->all(),
        );
        $storage = $request->getSession();
        $remaining = $this->session->recentRemaining($request);

        return $this->privateJson([
            'user' => $user, 'methods' => $methods, 'providers' => $providers,
            'csrf' => $this->csrf->getToken(self::PROFILE_CSRF)->getValue(),
            'logoutCsrf' => $this->csrf->getToken('dashboard-logout')->getValue(),
            'recent' => $remaining > 0, 'confirmation_remaining' => $remaining,
            'notices' => $storage instanceof FlashBagAwareSessionInterface ? $storage->getFlashBag()->all() : [],
        ]);
    }

    #[Route('/api/profile/token', name: 'api_profile_token', methods: ['GET'])]
    public function profileToken(Request $request): JsonResponse
    {
        if (!DashboardSession::secureForSignIn($request)) {
            return $this->privateJson(['error' => 'Use the dashboard’s HTTPS URL to update your profile.'], 403);
        }
        $account = $this->session->accountPrincipal($request);
        if (!$account || $request->query->getString('account') !== $account['subject']) {
            return $this->privateJson(['error' => self::PROFILE_ACCOUNT_CHANGED], 409);
        }

        return $this->privateJson(['profile' => $this->csrf->getToken(self::PROFILE_CSRF)->getValue()]);
    }

    #[Route('/api/profile/{action}', name: 'api_profile_edit', requirements: ['action' => 'password|unlink|revoke-sessions|reauthenticate'], methods: ['POST'])]
    public function updateProfile(Request $request, string $action): JsonResponse
    {
        if (!DashboardSession::secureForSignIn($request)) {
            return $this->privateJson(['error' => 'Use the dashboard’s HTTPS URL to update your profile.'], 403);
        }
        if (!$this->isCsrfTokenValid(self::PROFILE_CSRF, $request->headers->get('X-CSRF-Token', ''))) {
            return $this->privateJson(['error' => 'Your profile session expired. Reload and try again.', 'code' => 'csrf_expired'], 403);
        }
        $account = $this->session->accountPrincipal($request);
        if (!$account) {
            return $this->privateJson(['error' => 'Sign in with a managed PatchRocket account to change credentials.'], 403);
        }
        try {
            $payload = $request->toArray();
            if (array_key_exists('account', $payload) && $payload['account'] !== $account['subject']) {
                return $this->privateJson(['error' => self::PROFILE_ACCOUNT_CHANGED], 409);
            }
            if (in_array($action, ['password', 'reauthenticate'], true) &&
                !$this->accounts->rateLimit($request->getClientIp() ?? 'unknown')) {
                return $this->privateJson(['error' => 'Too many attempts. Try again in five minutes.'], 429);
            }
            if (in_array($action, ['unlink', 'revoke-sessions'], true) && !$this->session->recent($request)) {
                return $this->privateJson(self::PROFILE_CONFIRMATION_REQUIRED, 403);
            }
            if ('reauthenticate' === $action) {
                $this->session->confirmPassword($request, $this->text($payload, 'password'));
            }
            if ('password' === $action) {
                $updated = $this->accounts->changePassword($account, $this->text($payload, 'currentPassword'), $this->text($payload, 'password'));
                $this->session->updateAccount($request, $updated);
            }
            if ('unlink' === $action) {
                $this->accounts->unlink($account, $this->text($payload, 'id'));
            }
            if ('revoke-sessions' === $action) {
                $this->accounts->rotateSessions($account['subject'], $account['subject'], $account['version']);
            }
            $signedOut = in_array($action, ['unlink', 'revoke-sessions'], true);
            if ($signedOut) {
                $this->session->end($request);
            }

            return $this->privateJson(['ok' => true, 'signedOut' => $signedOut]);
        } catch (JsonException) {
            return $this->privateJson(['error' => 'Send a JSON object.'], 400);
        } catch (\DomainException $error) {
            return $this->privateJson(['error' => $error->getMessage()], 422);
        }
    }

    #[Route('/api/admin/users', name: 'api_admin_users', methods: ['GET'])]
    public function users(Request $request): JsonResponse
    {
        $query = $request->query;
        $accountView = fn (array $account): array => $account + ['methods' => $this->accounts->methods($account['username'])];
        $page = max(1, min(100000, $query->getInt('page', 1)));
        $directory = $query->has('page') ? $this->accounts->directory(
            trim($query->getString('q')), $query->getString('role'), $query->getString('state'), $page, $query->getString('edit'),
            $query->getBoolean('exact'),
        ) : null;
        $selected = $directory['selected'] ?? null;

        return $this->privateJson([
            'accounts' => array_map($accountView, $directory['rows'] ?? $this->accounts->all()),
            'roles' => DashboardAccounts::ROLES,
            'csrf' => $this->csrf->getToken(self::USERS_CSRF)->getValue(),
        ] + (null === $directory ? [] : ['page' => $page, 'next' => $directory['next'], 'selected' => $selected ? $accountView($selected) : null]));
    }

    #[Route('/api/admin/users/{username}', name: 'api_admin_users_save', requirements: ['username' => '[A-Za-z0-9][A-Za-z0-9._-]{1,39}'], methods: ['PUT'])]
    public function saveUser(Request $request, string $username): JsonResponse
    {
        if ($error = $this->usersTokenError($request)) {
            return $error;
        }
        try {
            $payload = $request->toArray();
            $disabled = $payload['disabled'] ?? null;
            if (null !== $disabled && !is_bool($disabled)) {
                throw new \DomainException('Choose whether account access is enabled.');
            }
            $mode = $payload['mode'] ?? null;
            if (null !== $mode && !in_array($mode, ['create', 'edit'], true)) {
                throw new \DomainException('Choose whether to create or edit the user.');
            }
            $this->accounts->save($username, $this->text($payload, 'password'), $this->text($payload, 'role'), $disabled,
                $request->attributes->get('_dashboard_actor'), $mode);

            return $this->privateJson(['ok' => true]);
        } catch (JsonException) {
            return $this->privateJson(['error' => 'Send a JSON object.'], 400);
        } catch (\DomainException $error) {
            return $this->privateJson(['error' => $error->getMessage()], 422);
        }
    }

    #[Route('/api/admin/users/{username}/revoke-sessions', name: 'api_admin_users_revoke', requirements: ['username' => '[a-z0-9][a-z0-9._-]{1,39}'], methods: ['POST'])]
    public function revokeUserSessions(Request $request, string $username): JsonResponse
    {
        if ($error = $this->usersTokenError($request)) {
            return $error;
        }
        try {
            $signedOut = ($this->session->accountPrincipal($request)['subject'] ?? null) === $username;
            $this->accounts->rotateSessions($username, $request->attributes->getString('_dashboard_actor'));
            if ($signedOut) {
                $this->session->end($request);
            }

            return $this->privateJson(['ok' => true, 'signedOut' => $signedOut]);
        } catch (\DomainException $error) {
            return $this->privateJson(['error' => $error->getMessage()], 422);
        }
    }

    private function usersTokenError(Request $request): ?JsonResponse
    {
        if (!DashboardSession::secureForSignIn($request)) {
            return $this->privateJson(['error' => 'Use the dashboard’s HTTPS URL to manage users.'], 403);
        }

        return $this->isCsrfTokenValid(self::USERS_CSRF, $request->headers->get('X-CSRF-Token', '')) ? null
            : $this->privateJson(['error' => 'Your settings session expired. Reload and try again.', 'code' => 'csrf_expired'], 403);
    }

    private function privateJson(array $data, int $status = 200): JsonResponse
    {
        return $this->json($data, $status, ['Cache-Control' => 'no-store']);
    }

    private function text(#[\SensitiveParameter] array $payload, string $field): string
    {
        $value = $payload[$field] ?? '';
        if (!is_string($value)) {
            throw new \DomainException('Enter valid text for '.$field.'.');
        }

        return $value;
    }
}
