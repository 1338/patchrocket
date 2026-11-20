<?php
declare(strict_types=1);

namespace App\Settings;

use App\Audit\Store;
use App\Secrets\SecretManagers;
use App\Secrets\SettingsCipher;

final class OperatorSettings
{
    public function __construct(private readonly Store $store)
    {
    }

    public function get(string $group): array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [$group])['data'] ?? [];
    }

    public function saveAi(array $input): void
    {
        $provider = $input['provider'] ?? '';
        $model = trim($input['model'] ?? '');
        $endpoint = trim($input['endpoint'] ?? '');
        $attempts = filter_var($input['limit'] ?? null, FILTER_VALIDATE_INT);
        if (!in_array($provider, ['off', 'ollama', 'openai', 'codex', 'replay'], true)
            || (in_array($provider, ['ollama', 'openai', 'codex'], true) && '' === $model)
            || strlen($model) > 200 || false === $attempts || $attempts < 0 || $attempts > 3) {
            throw new \DomainException('Choose a provider, a model when required, and an attempt limit from 0 to 3.');
        }
        if ('codex' === $provider && (!class_exists(\Symfony\AI\Platform\Bridge\Codex\Factory::class)
            || !in_array($_SERVER['APP_ENV'] ?? '', ['dev', 'test'], true))) {
            throw new \DomainException('Codex CLI fixtures are available in development installations.');
        }
        $effort = $input['effort'] ?? '';
        $levels = match ($provider) {
            'openai' => \App\AI\ModelDiscovery::openAiEfforts($model),
            'ollama' => ['off', 'on', 'low', 'medium', 'high'],
            'codex' => ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'],
            default => [],
        };
        if ('' !== $effort && !in_array($effort, $levels, true)) {
            throw new \DomainException('Choose an advertised effort level or use the provider default.');
        }
        $url = parse_url($endpoint);
        if (!is_array($url) || !in_array($url['scheme'] ?? null, ['http', 'https'], true) || empty($url['host'])
            || isset($url['user']) || isset($url['pass']) || isset($url['fragment']) || isset($url['query'])) {
            throw new \DomainException('Enter an HTTP or HTTPS Ollama endpoint without embedded credentials.');
        }
        $reference = trim($input['reference'] ?? '');
        if ('' !== $reference && (!preg_match('/^[a-z0-9][a-z0-9-]{0,31}:.+$/D', $reference) || strlen($reference) > 1057)) {
            throw new \DomainException('Enter a valid OpenAI credential reference.');
        }
        $existing = $this->get('ai');
        $secret = isset($input['clear_key']) ? '' : ($existing['secret'] ?? null);
        $key = trim($input['key'] ?? '');
        if ('' !== $key) {
            if (strlen($key) > 2048) {
                throw new \DomainException('The API key is too long.');
            }
            $secret = SettingsCipher::encrypt($key);
        }
        $this->save('ai', [
            'provider' => $provider, 'model' => $model, 'endpoint' => $endpoint, 'effort' => $effort,
            'limit' => $attempts, 'cloud_source' => isset($input['cloud_source']), 'secret' => $secret, 'reference' => $reference,
        ]);
    }

    public function aiKey(?string $secret, string $fallback): string
    {
        if (null === $secret || '' === $secret) {
            return $secret ?? $fallback;
        }
        return SettingsCipher::decrypt($secret);
    }

    public function saveScanner(int $timeout): void
    {
        if ($timeout < 30 || $timeout > 900) {
            throw new \DomainException('Choose a Trivy timeout between 30 and 900 seconds.');
        }
        $this->save('scanner', ['timeout' => $timeout]);
    }

    public function registries(): array
    {
        return array_map(static fn (array $row): string => $row['data']['host'],
            $this->store->rows("SELECT data FROM operator_settings WHERE id LIKE 'registry:%' ORDER BY id"));
    }

    public function saveRegistryReference(string $host, string $reference): void
    {
        $reference = trim($reference);
        if (!SecretManagers::validReference($reference)) {
            throw new \DomainException('Enter a credential reference in manager:secret format.');
        }
        $this->save($this->registryId($host), ['host' => strtolower(trim($host)), 'reference' => $reference]);
    }

    public function registryReference(string $host): ?string
    {
        return $this->get($this->registryId($host))['reference'] ?? null;
    }

    public function saveRegistry(string $host, string $username, #[\SensitiveParameter] string $password): void
    {
        $id = $this->registryId($host);
        if ('' === trim($username) || str_contains($username, ':') || '' === $password || strlen($username) > 200 || strlen($password) > 4096) {
            throw new \DomainException('Enter a registry username and pull token.');
        }
        $this->save($id, ['host' => strtolower(trim($host)), 'auth' => SettingsCipher::encrypt(base64_encode($username.':'.$password))]);
    }

    public function registryAuth(string $host): string
    {
        $row = $this->get($this->registryId($host));

        return $this->aiKey($row['auth'] ?? null, '');
    }

    public function removeRegistry(string $host): void
    {
        $this->store->db->delete('operator_settings', ['id' => $this->registryId($host)]);
    }

    private function registryId(string $host): string
    {
        $host = strtolower(trim($host));
        if (!preg_match('/^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?$/D', $host)) {
            throw new \DomainException('Enter one exact registry hostname, with an optional port.');
        }

        return 'registry:'.substr(hash('sha256', $host), 0, 48);
    }

    public function saveWorker(array $input): void
    {
        $image = trim($input['image'] ?? '');
        $network = trim($input['network'] ?? '');
        if (!preg_match('#^[a-zA-Z0-9][a-zA-Z0-9./_:@-]{0,250}$#D', $image)
            || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/D', $network)) {
            throw new \DomainException('Enter a local worker image and a Docker network name or none.');
        }
        $this->save('worker', ['image' => $image, 'network' => $network]);
    }

    private function save(string $id, array $settings): void
    {
        $this->store->put('operator_settings', ['id' => $id, 'data' => Store::json($settings)]);
    }
}
