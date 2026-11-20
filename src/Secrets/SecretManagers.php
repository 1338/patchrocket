<?php
declare(strict_types=1);

namespace App\Secrets;

use App\Audit\Store;
use Symfony\Component\Process\Process;

final class SecretManagers
{
    public const DASHBOARD_PATH = 'patchrocket/dashboard/';
    public const TYPES = [
        'aws' => 'AWS Secrets Manager',
        'azure' => 'Azure Key Vault',
        'gcp' => 'Google Cloud Secret Manager',
        'vault' => 'HashiCorp Vault KV',
        'onepassword' => '1Password',
    ];

    public function __construct(private readonly Store $store, private readonly AnsibleVault $ansible)
    {
    }

    public function all(): array
    {
        return array_map(static function (array $row): array {
            $row['data']['has_token'] = isset($row['data']['token']);
            $row['data']['has_writer_token'] = isset($row['data']['writer_token']);
            unset($row['data']['token'], $row['data']['writer_token'], $row['data']['ciphertext']);

            return $row;
        }, $this->store->rows("SELECT id, data FROM operator_settings WHERE id LIKE 'manager:%' ORDER BY id"));
    }

    public function save(
        string $name,
        string $type,
        string $scope,
        string $address = '',
        #[\SensitiveParameter] string $token = '',
        #[\SensitiveParameter] string $writer = '',
        bool $clearWriter = false,
    ): void
    {
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $name) || !isset(self::TYPES[$type])) {
            throw new \DomainException('Choose a short lowercase manager name and a supported provider.');
        }
        if (in_array($type, ['aws', 'gcp', 'vault'], true)
            && !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/D', $scope)) {
            throw new \DomainException('Enter the AWS region, Google Cloud project, or Vault KV mount.');
        }
        $existing = $this->manager($name);
        if (AnsibleVault::TYPE === ($existing['type'] ?? null)) {
            throw new \DomainException('This name is already used by an Ansible Vault import.');
        }
        $data = [
            'name' => $name, 'type' => $type, 'scope' => in_array($type, ['azure', 'onepassword'], true) ? '' : $scope,
        ];
        if ('vault' === $type) {
            $data += $this->vaultConnection($name, $address, $token, $existing ?? []);
            if ('' !== $writer) {
                if (!isset($data['address']) || $clearWriter) {
                    throw new \DomainException('Enter a Vault address and either set or remove the write token.');
                }
                $data['writer_token'] = $this->encryptVaultToken($writer, 'vault-writer:'.$name.':'.$data['address']);
            } elseif (!$clearWriter && isset($data['address'], $existing['writer_token'])
                && $data['address'] === $existing['address'] && $scope === $existing['scope']) {
                $data['writer_token'] = $existing['writer_token'];
            }
        }
        $this->writeManager($name, $data, $existing);
    }

    private function vaultConnection(string $name, string $address, #[\SensitiveParameter] string $token, array $existing): array
    {
        if ('' === $address) {
            if ('' !== $token) {
                throw new \DomainException('Enter a Vault address to save a token for this connection.');
            }

            return [];
        }
        $url = parse_url($address);
        $host = strtolower($url['host'] ?? '');
        $scheme = strtolower($url['scheme'] ?? '');
        if (strlen($address) > 512 || preg_match('/[\x00-\x20\\\\]/', $address) || !is_array($url)
            || array_diff(array_keys($url), ['scheme', 'host', 'port', 'path']) || !in_array($url['path'] ?? '', ['', '/'], true)
            || (isset($url['port']) && $url['port'] < 1)
            || (!filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) && !preg_match('/^[a-z0-9][a-z0-9.-]{0,252}$/D', $host))
            || ('https' !== $scheme && !('http' === $scheme && in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)))) {
            throw new \DomainException('Enter a Vault base URL. Remote Vault servers require HTTPS.');
        }
        $address = $scheme.'://'.$host.(isset($url['port']) ? ':'.$url['port'] : '');
        if ('' === $token) {
            if ($address !== ($existing['address'] ?? '') || !isset($existing['token'])) {
                throw new \DomainException('Enter a Vault token for this address.');
            }

            return ['address' => $address, 'token' => $existing['token']];
        }
        return ['address' => $address, 'token' => $this->encryptVaultToken($token, 'vault:'.$name.':'.$address)];
    }

    private function encryptVaultToken(#[\SensitiveParameter] string $token, string $context): string
    {
        if (strlen($token) > 4096 || preg_match('/[^\x21-\x7e]/', $token)) {
            throw new \DomainException('Enter a valid single-line Vault token.');
        }
        try {
            return SettingsCipher::encrypt($token, $context);
        } catch (\RuntimeException) {
            throw new \DomainException('Configure a stable application secret before storing a Vault token.');
        }
    }

    public function remove(string $name): void
    {
        $this->store->db->delete('operator_settings', ['id' => 'manager:'.$name]);
    }

    /** @return array<string, mixed> */
    public function bundle(string $reference): array
    {
        return $this->resolve($reference, true);
    }

    public function vaultDestinations(): array
    {
        return array_column(array_filter(array_column($this->all(), 'data'), static fn (array $data): bool =>
            'vault' === $data['type'] && isset($data['address']) && $data['has_token']), 'name');
    }

    public function storeVaultBundle(string $name, #[\SensitiveParameter] string $json): string
    {
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $name)) {
            throw new \DomainException('Choose a configured Vault KV manager.');
        }
        $data = $this->manager($name);
        if ('vault' !== ($data['type'] ?? null) || !isset($data['address'], $data['token'])) {
            throw new \DomainException('Choose a Vault KV manager with a saved address and token.');
        }
        $bundle = strlen($json) <= 100000 ? json_decode($json, depth: 32) : null;
        if (!$bundle instanceof \stdClass || [] === get_object_vars($bundle)) {
            throw new \DomainException('Enter a non-empty JSON credential object up to 100 KB.');
        }
        $path = self::DASHBOARD_PATH.bin2hex(random_bytes(16));
        $environment = $this->vaultEnvironment($data, true);
        $process = new Process(['vault', 'kv', 'put', '-mount='.$data['scope'], '-cas=0', $path, '-'],
            env: $environment, input: Store::json(['value' => $json]), timeout: 25);
        $process->disableOutput();
        try {
            if (0 === $process->run()) {
                return $name.':'.$path;
            }
        } catch (\Throwable) {
            // Vault diagnostics can contain credential values.
        }

        throw new \DomainException('Vault could not store the credential. Check the KV v2 mount and the token’s create access to '.self::DASHBOARD_PATH.'.');
    }

    public function importAnsible(string $name, string $passwordReference, #[\SensitiveParameter] string $ciphertext, string $mapping): int
    {
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $name)) {
            throw new \DomainException('Choose a short lowercase manager name.');
        }

        $existing = $this->manager($name);
        if (null !== $existing && AnsibleVault::TYPE !== $existing['type']) {
            throw new \DomainException('That name is already used by another secrets manager.');
        }

        $fields = $this->ansible->fields($mapping);
        $names = array_keys($this->ansible->bundles($ciphertext, $this->vaultPassword($passwordReference), $fields));
        $this->writeManager($name, [
            'name' => $name, 'type' => AnsibleVault::TYPE, 'scope' => $passwordReference,
            'ciphertext' => $ciphertext, 'fields' => $fields, 'bundles' => $names,
        ], $existing);

        return count($names);
    }

    private function writeManager(string $name, array $data, ?array $existing): void
    {
        if ($data === $existing) {
            return;
        }
        $id = 'manager:'.$name;
        $written = null === $existing
            ? $this->store->db->executeStatement('INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING', [$id, Store::json($data)])
            : $this->store->db->update('operator_settings', ['data' => Store::json($data)], ['id' => $id, 'data' => Store::json($existing)]);
        if (1 !== $written) {
            throw new \DomainException('The secrets manager changed during the edit. Refresh and try again.');
        }
    }

    private function manager(string $name): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', ['manager:'.$name])['data'] ?? null;
    }

    private function vaultPassword(string $reference): string
    {
        $password = $this->resolve($reference, false)['password'] ?? null;
        if (!is_string($password) || '' === trim($password) || strlen($password) > 4096 || strpbrk($password, "\0\r\n") !== false) {
            throw new \DomainException('The password reference must contain a single-line Ansible Vault password in the password field.');
        }

        return $password;
    }

    private function resolve(string $reference, bool $allowAnsibleVault): array
    {
        if (!self::validReference($reference)) {
            throw new \DomainException('Use a managed credential reference in manager:secret format.');
        }
        [$manager, $locator] = explode(':', $reference, 2);

        $data = $this->manager($manager);
        if (!$data) {
            throw new \DomainException('The referenced secrets manager is unavailable.');
        }
        $scope = $data['scope'];
        if (AnsibleVault::TYPE === $data['type']) {
            if (!$allowAnsibleVault) {
                throw new \DomainException('Store the Ansible Vault password in an external secrets manager.');
            }
            if (!in_array($locator, $data['bundles'], true)) {
                throw new \DomainException('The requested credential does not exist in this Ansible Vault.');
            }

            return $this->ansible->bundles($data['ciphertext'], $this->vaultPassword($scope), $data['fields'])[$locator];
        }
        $args = match ($data['type']) {
            'aws' => ['aws', '--no-cli-pager', 'secretsmanager', 'get-secret-value', '--secret-id='.$locator, '--region='.$scope, '--query', 'SecretString', '--output', 'text'],
            'azure' => ['az', 'keyvault', 'secret', 'show', '--id='.$this->azureId($locator), '--query', 'value', '--output', 'tsv', '--only-show-errors'],
            'gcp' => ['gcloud', 'secrets', 'versions', 'access', 'latest', '--secret='.$locator, '--project='.$scope, '--quiet'],
            'vault' => ['vault', 'kv', 'get', '-mount='.$scope, '-field=value', $locator],
            'onepassword' => ['op', 'read', $this->opReference($locator)],
            default => throw new \DomainException('Unsupported secrets manager.'),
        };

        return $this->decode($args, 'vault' === $data['type'] ? $this->vaultEnvironment($data) : []);
    }

    private function vaultEnvironment(#[\SensitiveParameter] array $data, bool $write = false): array
    {
        if (!isset($data['address'])) {
            return [];
        }
        try {
            $field = $write && isset($data['writer_token']) ? 'writer_token' : 'token';
            $context = 'writer_token' === $field ? 'vault-writer:' : 'vault:';
            $token = SettingsCipher::decrypt($data[$field], $context.$data['name'].':'.$data['address']);
        } catch (\RuntimeException | \TypeError) {
            throw new \DomainException('The saved Vault token could not be read. Replace it in Settings.');
        }

        return [
            'VAULT_ADDR' => $data['address'], 'VAULT_TOKEN' => $token,
            'VAULT_DISABLE_REDIRECTS' => 'true', 'VAULT_SKIP_VERIFY' => 'false', 'VAULT_SRV_LOOKUP' => 'false',
            'VAULT_AGENT_ADDR' => false, 'VAULT_PROXY_ADDR' => false, 'VAULT_HTTP_PROXY' => false, 'VAULT_NAMESPACE' => false,
            'VAULT_TLS_SERVER_NAME' => false, 'VAULT_CLIENT_CERT' => false, 'VAULT_CLIENT_KEY' => false,
        ];
    }

    public static function validReference(string $reference): bool
    {
        return (bool) preg_match('/^[a-z0-9][a-z0-9-]{0,31}:[^\x00-\x1f-][^\x00-\x1f]{0,1023}$/D', $reference);
    }

    /** @return array<string, mixed> */
    private function decode(array $args, #[\SensitiveParameter] array $env = []): array
    {
        $process = new Process($args, env: $env, timeout: 25);
        try {
            $process->setInput('');
            $size = 0;
            $status = $process->run(static function (string $type, string $chunk) use (&$size): void {
                $size += strlen($chunk);
                if ($size > 131072) {
                    throw new \DomainException('The managed credential exceeded its size limit.');
                }
            });
            $raw = $process->getOutput();
            $process->clearOutput();
            $process->clearErrorOutput();
            $bundle = 0 === $status ? json_decode($raw, true, flags: JSON_THROW_ON_ERROR) : null;
            if (is_array($bundle) && !array_is_list($bundle)) {
                return $bundle;
            }
        } catch (\Throwable) {
            // Never expose provider output, command exceptions, or a secret value.
        }
        throw new \DomainException('Could not read a JSON credential bundle from the secrets manager. Check its identity and reference.');
    }

    private function azureId(string $id): string
    {
        if (!preg_match('#^https://[a-zA-Z0-9-]+\.vault\.(?:azure\.net|usgovcloudapi\.net|azure\.cn)/secrets/[a-zA-Z0-9-]+(?:/[a-zA-Z0-9]+)?$#D', $id)) {
            throw new \DomainException('Enter a complete Azure Key Vault secret identifier.');
        }

        return $id;
    }

    private function opReference(string $reference): string
    {
        if (!str_starts_with($reference, 'op://')) {
            throw new \DomainException('Enter a 1Password op:// field reference.');
        }

        return $reference;
    }
}
