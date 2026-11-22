<?php
declare(strict_types=1);

namespace App\Auth;

use App\Audit\Store;

final class DashboardAccounts
{
    public const ROLES = ['viewer' => 'Viewer', 'operator' => 'Operator', 'admin' => 'Administrator'];
    private const BOOTSTRAP = 'auth:bootstrap';
    private const LOCAL_PREFIX = 'auth:local:';
    private const LINK_PREFIX = 'auth:link:';
    private const PAGE_SIZE = 25;
    private const DUMMY_HASH = '$2y$12$RjoNCF6pYT8eKdRsRTC3uOVcoT8F4wScQiJ4000cnVSiBM/5ZUFPa';

    public function __construct(private readonly Store $store)
    {
    }

    public function state(): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::BOOTSTRAP])['data'] ?? null;
    }

    public function issueBootstrap(): string
    {
        $otp = bin2hex(random_bytes(20));
        $data = ['hash' => hash('sha256', $otp), 'expires' => time() + 1800, 'initialized' => false];
        $current = $this->state();
        if ($current['initialized'] ?? false) {
            throw new \DomainException('The initial administrator is already configured.');
        }
        $this->write(self::BOOTSTRAP, $data, $current);

        return $otp;
    }

    public function setup(string $username, #[\SensitiveParameter] string $password, #[\SensitiveParameter] string $otp): array
    {
        $username = $this->username($username);
        $passwordHash = $this->passwordHash($password);
        $current = $this->state();
        if (!$current || $current['initialized'] || $current['expires'] <= time()
            || strlen($otp) !== 40 || !hash_equals($current['hash'], hash('sha256', $otp))) {
            throw new \DomainException('The setup code is invalid or expired. Generate a new one from the console.');
        }
        $account = ['username' => $username, 'role' => 'admin', 'password' => $passwordHash, 'version' => $this->version(), 'bootstrap' => true];
        $this->store->db->transactional(function () use ($account, $current): void {
            $this->write(self::BOOTSTRAP, ['initialized' => true], $current);
            $this->write(self::LOCAL_PREFIX.$account['username'], $account, null);
        });

        return $this->principal($account);
    }

    public function login(string $username, #[\SensitiveParameter] string $password): ?array
    {
        if (strlen($password) > 72 || str_contains($password, "\0")) {
            return null;
        }
        $username = strtolower(trim($username));
        $account = $this->account($username);
        if (!password_verify($password, $account['password'] ?? self::DUMMY_HASH) || !$account || ($account['disabled'] ?? false)) {
            return null;
        }

        return $this->principal($account);
    }

    public function authenticated(array $principal): ?array
    {
        $account = $this->account($principal['subject']);

        return $account && !($account['disabled'] ?? false) && $account['version'] === $principal['version']
            ? ['role' => $account['role'], 'label' => $account['username']]
            : null;
    }

    public function all(): array
    {
        return array_map(static fn (array $row): array => self::accountView($row['data']),
            $this->store->rows("SELECT data FROM operator_settings WHERE id LIKE 'auth:local:%' ORDER BY id"));
    }

    public function directory(string $search, string $role, string $state, int $page, string $edit, bool $exactUsername = false): array
    {
        $conditions = ["id LIKE 'auth:local:%'"];
        $params = [];
        if ($exactUsername && '' !== $search) {
            $conditions[] = 'id = ?';
            $params[] = self::LOCAL_PREFIX.strtolower($search);
        } elseif ('' !== $search) {
            $conditions[] = "LOWER(".$this->store->jsonText('data', 'username').") LIKE LOWER(?) ESCAPE '!'";
            $params[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }
        if (isset(self::ROLES[$role])) {
            $conditions[] = $this->store->jsonText('data', 'role').' = ?';
            $params[] = $role;
        }
        if (in_array($state, ['enabled', 'disabled'], true)) {
            $disabled = "COALESCE(".$this->store->jsonText('data', 'disabled').", 'false') IN ('true', '1')";
            $conditions[] = 'disabled' === $state ? $disabled : 'NOT ('.$disabled.')';
        }
        $where = implode(' AND ', $conditions);
        $limit = self::PAGE_SIZE + 1;
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rows = $this->store->rows("SELECT data FROM operator_settings WHERE $where ORDER BY id LIMIT $limit OFFSET $offset", $params);
        $selected = $this->account($edit);

        return [
            'rows' => array_map(static fn (array $row): array => self::accountView($row['data']), array_slice($rows, 0, self::PAGE_SIZE)),
            'next' => count($rows) > self::PAGE_SIZE,
            'selected' => $selected ? self::accountView($selected) : null,
        ];
    }

    private static function accountView(array $data): array
    {
        $data['disabled'] ??= false;
        unset($data['password'], $data['version']);

        return $data;
    }

    public function save(
        string $username,
        #[\SensitiveParameter] string $password,
        string $role,
        ?bool $disabled = null,
        ?string $actor = null,
        ?string $mode = null,
    ): void
    {
        $username = $this->username($username);
        $this->store->db->transactional(function () use ($username, $password, $role, $disabled, $actor, $mode): void {
            $existing = $this->account($username);
            if ('create' === $mode && $existing) {
                throw new \DomainException('A user with this username already exists. Choose another username or edit that user.');
            }
            if ('edit' === $mode && !$existing) {
                throw new \DomainException('This user is no longer available. Return to Users and choose an account.');
            }
            $previouslyDisabled = $existing['disabled'] ?? false;
            $disabled ??= $previouslyDisabled;
            if (!isset(self::ROLES[$role]) || (($existing['bootstrap'] ?? false) && ('admin' !== $role || $disabled))) {
                throw new \DomainException('Choose a valid role. The first administrator retains administrative access.');
            }
            if ($existing && '' === $password && $role === $existing['role'] && $disabled === $previouslyDisabled) {
                return;
            }
            $this->write(self::LOCAL_PREFIX.$username, [
                'username' => $username, 'role' => $role,
                'password' => '' === $password && $existing ? $existing['password'] : $this->passwordHash($password),
                'version' => $this->version(), 'bootstrap' => $existing['bootstrap'] ?? false, 'disabled' => $disabled,
            ], $existing);
            if (null !== $actor) {
                $this->store->record('auth', $existing ? 'account.updated' : 'account.created', [
                    'actor' => $actor, 'account' => $username, 'role' => $role, 'disabled' => $disabled, 'password_changed' => '' !== $password,
                ]);
            }
        });
    }

    public function remove(string $username, ?string $actor = null): void
    {
        $username = $this->username($username);
        $existing = $this->account($username);
        if (!$existing || $existing['bootstrap']) {
            throw new \DomainException('Choose a local account other than the first administrator.');
        }
        $this->store->db->transactional(function () use ($username, $existing, $actor): void {
            if ($this->links($username)) {
                throw new \DomainException('Disable accounts that have linked sign-in methods.');
            }
            if (1 !== $this->store->db->delete('operator_settings', ['id' => self::LOCAL_PREFIX.$username, 'data' => Store::json($existing)])) {
                throw new \DomainException('The account changed. Refresh and try again.');
            }
            if (null !== $actor) {
                $this->store->record('auth', 'account.removed', ['actor' => $actor, 'account' => $username]);
            }
        });
    }

    public function methods(string $username): array
    {
        return [['id' => 'password', 'type' => 'password', 'label' => 'Password'], ...array_values($this->links($username))];
    }

    public function linked(array $provider, string $subject): ?array
    {
        $id = $this->methodId($provider, $subject);

        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::LINK_PREFIX.$id])['data'] ?? null;
    }

    public function link(array $accountPrincipal, array $provider, array $identity): array
    {
        $username = $accountPrincipal['subject'];
        $id = $this->methodId($provider, $identity['subject']);
        return $this->store->db->transactional(function () use ($accountPrincipal, $provider, $identity, $username, $id): array {
            $account = $this->account($username);
            if (!$account || !$this->authenticated($accountPrincipal)) {
                throw new \DomainException('Sign in to your account before linking a method.');
            }
            $existing = $this->linked($provider, $identity['subject']);
            if ($existing['enabled'] ?? false) {
                throw new \DomainException($existing['account'] === $username
                    ? 'That sign-in method is already linked to this account.'
                    : 'That sign-in method is already linked to another account.');
            }
            $this->write(self::LINK_PREFIX.$id, [
                'id' => $id, 'type' => $provider['type'], 'account' => $username, 'provider' => $provider['alias'],
                'subject' => $identity['subject'], 'label' => $identity['label'], 'enabled' => true,
            ], $existing);
            $updated = array_replace($account, ['version' => $this->version()]);
            $this->write(self::LOCAL_PREFIX.$username, $updated, $account);
            $this->store->record('auth', 'identity.linked', ['actor' => $username, 'account' => $username, 'provider' => $provider['alias']]);

            return $this->principal($updated);
        });
    }

    public function unlink(array $principal, string $id): void
    {
        $username = $principal['subject'];
        if (!$this->authenticated($principal) || !preg_match('/^[a-f0-9]{64}$/D', $id)) {
            throw new \DomainException('Choose a linked provider sign-in method.');
        }
        $this->store->db->transactional(function () use ($principal, $username, $id): void {
            $link = $this->links($username)[$id] ?? null;
            if (!$link) {
                throw new \DomainException('Choose a linked provider sign-in method.');
            }
            $existing = $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::LINK_PREFIX.$id])['data'];
            $this->write(self::LINK_PREFIX.$id, array_replace($existing, ['enabled' => false]), $existing);
            $this->rotateSessions($username, $username, $principal['version']);
            $this->store->record('auth', 'identity.unlinked', ['actor' => $username, 'account' => $username, 'provider' => $link['provider']]);
        });
    }

    public function linkedPrincipal(array $link, array $identity): ?array
    {
        $account = ($link['enabled'] ?? false) ? $this->account($link['account']) : null;
        if (!$account || ($account['disabled'] ?? false)) {
            return null;
        }

        return $identity + ['account' => $this->principal($account), 'method' => $link['id']];
    }

    public function rotateSessions(string $username, string $actor, ?string $version = null): void
    {
        $this->store->db->transactional(function () use ($username, $actor, $version): void {
            $existing = $this->account($username);
            if (!$existing || (null !== $version && $existing['version'] !== $version)) {
                throw new \DomainException('The account changed. Sign in and try again.');
            }
            $this->write(self::LOCAL_PREFIX.$username, array_replace($existing, ['version' => $this->version()]), $existing);
            $this->store->record('auth', 'sessions.revoked', ['actor' => $actor, 'account' => $username]);
        });
    }

    public function changePassword(array $principal, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $password): array
    {
        $username = $principal['subject'];
        $existing = $this->account($username);
        if (!$existing || !$this->authenticated($principal) || $this->login($username, $current) !== $principal) {
            throw new \DomainException('Enter the current account password.');
        }
        $updated = array_replace($existing, ['password' => $this->passwordHash($password), 'version' => $this->version()]);
        $this->store->db->transactional(function () use ($username, $existing, $updated): void {
            $this->write(self::LOCAL_PREFIX.$username, $updated, $existing);
            $this->store->record('auth', 'password.changed', ['actor' => $username, 'account' => $username]);
        });

        return $this->principal($updated);
    }

    private function links(string $username): array
    {
        $links = [];
        foreach ($this->store->iterate("SELECT data FROM operator_settings WHERE id LIKE 'auth:link:%' ORDER BY id") as $row) {
            $data = $row['data'];
            if ($data['account'] === $username && $data['enabled']) {
                unset($data['enabled'], $data['account']);
                $links[$data['id']] = $data;
            }
        }

        return $links;
    }

    private function methodId(array $provider, string $subject): string
    {
        return hash('sha256', Store::json([
            $provider['issuer'], 'facebook' === $provider['type'] ? $provider['client_id'] : '', $subject,
        ]));
    }

    public function rateLimit(string $address): bool
    {
        $key = hash('sha256', $address);
        $now = time();
        $this->store->db->executeStatement('DELETE FROM dashboard_auth_attempts WHERE expires_at <= ?', [$now]);
        $this->store->db->executeStatement(
            'INSERT INTO dashboard_auth_attempts (id, attempts, expires_at) VALUES (?, 1, ?)
             ON CONFLICT (id) DO UPDATE SET attempts = CASE WHEN dashboard_auth_attempts.attempts < 10 THEN dashboard_auth_attempts.attempts + 1 ELSE 10 END',
            [$key, $now + 300],
        );

        return (int) $this->store->db->fetchOne('SELECT attempts FROM dashboard_auth_attempts WHERE id = ?', [$key]) < 10;
    }

    private function account(string $username): ?array
    {
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{1,39}$/D', $username)) {
            return null;
        }

        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::LOCAL_PREFIX.$username])['data'] ?? null;
    }

    private function principal(array $account): array
    {
        return ['type' => 'local', 'subject' => $account['username'], 'version' => $account['version']];
    }

    private function username(string $username): string
    {
        $username = strtolower(trim($username));
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{1,39}$/D', $username)) {
            throw new \DomainException('Enter a username of 2 to 40 letters, digits, dots, underscores or hyphens.');
        }

        return $username;
    }

    private function passwordHash(#[\SensitiveParameter] string $password): string
    {
        if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
            throw new \DomainException('Enter a password between 12 and 72 bytes.');
        }

        return password_hash($password, PASSWORD_DEFAULT);
    }

    private function version(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function write(string $id, #[\SensitiveParameter] array $data, #[\SensitiveParameter] ?array $previous): void
    {
        $count = null === $previous
            ? $this->store->db->executeStatement('INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING', [$id, Store::json($data)])
            : $this->store->db->update('operator_settings', ['data' => Store::json($data)], ['id' => $id, 'data' => Store::json($previous)]);
        if (1 !== $count) {
            throw new \DomainException('The authentication settings changed. Refresh and try again.');
        }
    }
}
