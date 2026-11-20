<?php
declare(strict_types=1);

namespace App\Auth;

use App\Audit\Store;

final class DashboardAccounts
{
    public const ROLES = ['viewer' => 'Viewer', 'operator' => 'Operator', 'admin' => 'Administrator'];
    private const BOOTSTRAP = 'auth:bootstrap';
    private const LOCAL_PREFIX = 'auth:local:';
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
        if (!password_verify($password, $account['password'] ?? self::DUMMY_HASH) || !$account) {
            return null;
        }

        return $this->principal($account);
    }

    public function authenticated(array $principal): ?array
    {
        $account = $this->account($principal['subject']);

        return $account && $account['version'] === $principal['version']
            ? ['role' => $account['role'], 'label' => $account['username']]
            : null;
    }

    public function all(): array
    {
        return array_map(static function (array $row): array {
            $data = $row['data'];
            unset($data['password'], $data['version']);

            return $data;
        }, $this->store->rows("SELECT data FROM operator_settings WHERE id LIKE 'auth:local:%' ORDER BY id"));
    }

    public function save(string $username, #[\SensitiveParameter] string $password, string $role): void
    {
        $username = $this->username($username);
        $existing = $this->account($username);
        if (!isset(self::ROLES[$role]) || (($existing['bootstrap'] ?? false) && 'admin' !== $role)) {
            throw new \DomainException('Choose a valid role. The first administrator retains administrative access.');
        }
        if ($existing && '' === $password && $role === $existing['role']) {
            return;
        }
        $this->write(self::LOCAL_PREFIX.$username, [
            'username' => $username, 'role' => $role,
            'password' => '' === $password && $existing ? $existing['password'] : $this->passwordHash($password),
            'version' => $this->version(), 'bootstrap' => $existing['bootstrap'] ?? false,
        ], $existing);
    }

    public function remove(string $username): void
    {
        $username = $this->username($username);
        $existing = $this->account($username);
        if (!$existing || $existing['bootstrap']) {
            throw new \DomainException('Choose a local account other than the first administrator.');
        }
        $this->store->db->delete('operator_settings', ['id' => self::LOCAL_PREFIX.$username, 'data' => Store::json($existing)]);
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
