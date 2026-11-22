<?php
declare(strict_types=1);

namespace App\Auth;

use App\Audit\Store;
use App\Secrets\SecretManagers;
use App\Secrets\SettingsCipher;

final class IdentityProviders
{
    public const TYPES = [
        'oidc' => 'OpenID Connect', 'microsoft' => 'Microsoft Entra ID', 'google' => 'Google',
        'facebook' => 'Facebook Login', 'github' => 'GitHub',
    ];
    private const PREFIX = 'auth:idp:';

    public function __construct(private readonly Store $store, private readonly SecretManagers $secrets)
    {
    }

    public function all(): array
    {
        return array_map(static function (array $row): array {
            $data = $row['data'];
            $data['has_secret'] = isset($data['secret']);
            unset($data['secret'], $data['version']);

            return $data;
        }, $this->store->rows("SELECT data FROM operator_settings WHERE id LIKE 'auth:idp:%' ORDER BY id"));
    }

    public function get(string $alias): ?array
    {
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $alias)) {
            return null;
        }

        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::PREFIX.$alias])['data'] ?? null;
    }

    public function save(#[\SensitiveParameter] array $input): void
    {
        $alias = strtolower(trim($input['alias'] ?? ''));
        $type = $input['type'] ?? '';
        $client = trim($input['client_id'] ?? '');
        $scope = trim($input['additional_scopes'] ?? '');
        $claim = trim($input['claim'] ?? '');
        $default = $input['default_role'] ?? '';
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $alias) || !isset(self::TYPES[$type])
            || !preg_match('/^[a-zA-Z0-9._:-]{1,255}$/D', $client)
            || !in_array($default, ['', 'viewer'], true)
            || ('' !== $claim && !preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D', $claim))
            || ('' !== $scope && !preg_match('~^[a-zA-Z0-9_:/.-]+(?: [a-zA-Z0-9_:/.-]+)*$~D', $scope))
            || strlen($scope) > 255) {
            throw new \DomainException('Check the provider alias, client ID, scopes and default access.');
        }
        $issuer = match ($type) {
            'google' => 'https://accounts.google.com',
            'microsoft' => $this->entraIssuer(trim($input['issuer'] ?? '')),
            'oidc' => $this->issuer(trim($input['issuer'] ?? '')),
            'github' => 'https://github.com',
            'facebook' => 'https://www.facebook.com',
        };
        $subjects = $this->rules($input['subjects'] ?? '');
        $claims = $this->rules($input['claims'] ?? '');
        if ($claims && (!$claim || in_array($type, ['github', 'facebook'], true))) {
            throw new \DomainException('Claim mapping requires an OIDC provider and a claim name.');
        }
        $data = [
            'alias' => $alias, 'type' => $type, 'client_id' => $client, 'issuer' => $issuer,
            'default_role' => $default, 'claim' => $claim, 'subjects' => $subjects, 'claims' => $claims,
            'additional_scopes' => $scope,
        ];
        $existing = $this->get($alias);
        $reference = trim($input['reference'] ?? '');
        $secret = $input['secret'] ?? '';
        if ('' !== $reference) {
            if ('' !== $secret || !SecretManagers::validReference($reference)) {
                throw new \DomainException('Enter one valid credential reference or a client secret.');
            }
            $data['reference'] = $reference;
        } elseif ('' !== $secret) {
            $data['secret'] = SettingsCipher::encrypt($this->validateSecret($secret), $this->cipherContext($data));
        } elseif (isset($existing['secret']) && $this->cipherContext($existing) === $this->cipherContext($data)) {
            $data['secret'] = $existing['secret'];
        } else {
            throw new \DomainException('Enter the client secret or select a managed credential.');
        }
        $data['version'] = bin2hex(random_bytes(16));
        $id = self::PREFIX.$alias;
        $written = null === $existing
            ? $this->store->db->executeStatement('INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING', [$id, Store::json($data)])
            : $this->store->db->update('operator_settings', ['data' => Store::json($data)], ['id' => $id, 'data' => Store::json($existing)]);
        if (1 !== $written) {
            throw new \DomainException('The provider was changed concurrently. Refresh and try again.');
        }
    }

    public function remove(string $alias): void
    {
        if ($provider = $this->get($alias)) {
            $this->store->db->delete('operator_settings', ['id' => self::PREFIX.$alias, 'data' => Store::json($provider)]);
        }
    }

    public function secret(#[\SensitiveParameter] array $provider): string
    {
        try {
            $secret = isset($provider['reference'])
                ? ($this->secrets->bundle($provider['reference'])['client_secret'] ?? '')
                : SettingsCipher::decrypt($provider['secret'], $this->cipherContext($provider));
        } catch (\RuntimeException) {
            throw new \DomainException('The identity provider credential is unavailable.');
        }
        if (!is_string($secret)) {
            throw new \DomainException('The identity provider credential is invalid.');
        }

        return $this->validateSecret($secret);
    }

    public function authenticated(array $principal): ?array
    {
        $provider = $this->get($principal['provider']);
        if (!$provider || $provider['version'] !== $principal['version']) {
            return null;
        }
        $role = $provider['subjects'][$principal['subject']] ?? null;
        if (null === $role) {
            $roles = array_intersect_key($provider['claims'], array_fill_keys($principal['claims'], true));
            if (in_array('', $roles, true)) {
                return null;
            }
            foreach (array_reverse(array_keys(DashboardAccounts::ROLES)) as $candidate) {
                if (in_array($candidate, $roles, true)) {
                    $role = $candidate;
                    break;
                }
            }
            $role ??= $provider['default_role'];
        }

        return '' === $role ? null : ['role' => $role, 'label' => $principal['label'], 'provider' => $provider['alias'], 'subject' => $principal['subject']];
    }

    public function blocked(array $provider, array $principal): bool
    {
        if (array_key_exists($principal['subject'], $provider['subjects'])) {
            return '' === $provider['subjects'][$principal['subject']];
        }

        return in_array('', array_intersect_key($provider['claims'], array_fill_keys($principal['claims'], true)), true);
    }

    private function rules(string $input): array
    {
        $rules = [];
        if (strlen($input) > 20000) {
            throw new \DomainException('Role mappings are limited to 20 KB.');
        }
        foreach (preg_split('/\R/', trim($input)) as $line) {
            if ('' === trim($line)) {
                continue;
            }
            if (!preg_match('/^([^=\x00-\x1f]{1,255})\s*=\s*(viewer|operator|admin|deny)$/D', trim($line), $match)) {
                throw new \DomainException('Enter each role mapping on its own line as value=role.');
            }
            $key = trim($match[1]);
            if ('' === $key || array_key_exists($key, $rules)) {
                throw new \DomainException('Role mappings must have distinct, non-empty values.');
            }
            $rules[$key] = 'deny' === $match[2] ? '' : $match[2];
        }

        return $rules;
    }

    private function issuer(string $url): string
    {
        if (strlen($url) > 512 || !preg_match('#^https://[a-zA-Z0-9.-]+(?::[0-9]{1,5})?(?:/[a-zA-Z0-9._/~-]*)?$#D', $url)) {
            throw new \DomainException('Enter the exact HTTPS issuer from the provider metadata.');
        }

        return $url;
    }

    private function entraIssuer(string $value): string
    {
        if (preg_match('/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/Di', $value)) {
            $value = 'https://login.microsoftonline.com/'.strtolower($value).'/v2.0';
        }
        if (!preg_match('~^https://login\.microsoftonline\.com/[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}/v2\.0$~D', $value)) {
            throw new \DomainException('Enter the Microsoft Entra tenant ID or its tenant-specific v2 issuer.');
        }

        return $value;
    }

    private function cipherContext(array $provider): string
    {
        return 'dashboard-idp:'.$provider['alias'].':'.$provider['issuer'].':'.$provider['client_id'];
    }

    private function validateSecret(#[\SensitiveParameter] string $secret): string
    {
        if ('' === $secret || strlen($secret) > 4096 || preg_match('/[\x00-\x20\x7f]/', $secret)) {
            throw new \DomainException('Enter a valid single-line client secret.');
        }

        return $secret;
    }
}
