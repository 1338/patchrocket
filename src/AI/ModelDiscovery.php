<?php
declare(strict_types=1);

namespace App\AI;

use Symfony\Contracts\HttpClient\HttpClientInterface;

final class ModelDiscovery
{
    public function __construct(private readonly HttpClientInterface $http)
    {
    }

    public function discover(string $provider, string $endpoint, #[\SensitiveParameter] string $key, string $model): array
    {
        return match ($provider) {
            'ollama' => $this->ollama($endpoint, $model),
            'openai' => $this->openAi($key, $model),
            'codex' => $this->codex($model),
            default => ['models' => [], 'efforts' => []],
        };
    }

    private function ollama(string $endpoint, string $model): array
    {
        $url = parse_url($endpoint);
        if (!$url || !in_array($url['scheme'] ?? '', ['http', 'https'], true) || empty($url['host'])
            || isset($url['user'], $url['pass']) || isset($url['user']) || isset($url['query']) || isset($url['fragment'])) {
            throw new \DomainException('Enter a valid Ollama server URL.');
        }
        $endpoint = rtrim($endpoint, '/');
        if ('' !== $model) {
            $metadata = $this->request('POST', $endpoint.'/api/show', ['json' => ['model' => $model]]);
            $efforts = [];
            if (in_array('thinking', $metadata['capabilities'] ?? [], true)) {
                $efforts = 'gptoss' === ($metadata['details']['family'] ?? '') || preg_match('/(?:^|\/)gpt-oss:/i', $model)
                    ? ['low', 'medium', 'high'] : ['off', 'on'];
            }

            return ['models' => [], 'efforts' => $efforts];
        }

        $metadata = $this->request('GET', $endpoint.'/api/tags');

        return ['models' => $this->names(array_column($metadata['models'] ?? [], 'name')), 'efforts' => []];
    }

    private function openAi(#[\SensitiveParameter] string $key, string $model): array
    {
        if ('' !== $model) {
            return ['models' => [], 'efforts' => self::openAiEfforts($model)];
        }
        if ('' === $key) {
            throw new \DomainException('Save or enter an OpenAI API key to list account models.');
        }
        $response = $this->request('GET', 'https://api.openai.com/v1/models', ['auth_bearer' => $key]);
        $models = array_filter(array_column($response['data'] ?? [], 'id'), static fn (string $name): bool =>
            preg_match('/^(?:gpt|o[134])[-.]/', $name) && !preg_match('/audio|image|realtime|transcribe|tts|search|instruct/', $name));

        return ['models' => $this->names($models), 'efforts' => []];
    }

    public static function openAiEfforts(string $model): array
    {
        // Models/list does not report effort support. Offer only the documented subset for recognized families.
        return match (true) {
            (bool) preg_match('/^gpt-6(?:[.-]|$)/', $model) => ['low', 'medium', 'high', 'xhigh'],
            (bool) preg_match('/^gpt-5\.[23456](?:-|$)/', $model) && !str_contains($model, 'pro') => ['low', 'medium', 'high', 'xhigh'],
            (bool) preg_match('/^gpt-5(?:-(?:mini|nano|\d{4})|$)/', $model) => ['minimal', 'low', 'medium', 'high'],
            (bool) preg_match('/^(?:o3|o4-mini)(?:-\d{4}|$)/', $model) => ['low', 'medium', 'high'],
            default => [],
        };
    }

    private function codex(string $model): array
    {
        if (!class_exists(\Symfony\AI\Platform\Bridge\Codex\Factory::class) || !in_array($_SERVER['APP_ENV'] ?? '', ['dev', 'test'], true)) {
            throw new \DomainException('Codex model discovery is available in development installations.');
        }
        $home = getenv('CODEX_HOME') ?: rtrim(getenv('HOME') ?: '', '/').'/.codex';
        $path = $home.'/models_cache.json';
        if (!is_file($path) || filesize($path) > 5000000) {
            throw new \DomainException('The Codex CLI model catalog cache is unavailable. A logged-in Codex CLI session populates it.');
        }
        $catalog = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
        $models = [];
        $efforts = [];
        foreach ($catalog['models'] ?? [] as $entry) {
            if ('list' !== ($entry['visibility'] ?? null) || !is_string($entry['slug'] ?? null)) {
                continue;
            }
            $models[] = $entry['slug'];
            if ($entry['slug'] === $model) {
                $efforts = array_values(array_intersect(
                    array_column($entry['supported_reasoning_levels'] ?? [], 'effort'),
                    ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'],
                ));
            }
        }

        return ['models' => '' === $model ? $this->names($models) : [], 'efforts' => $efforts];
    }

    private function names(array $models): array
    {
        $models = array_values(array_unique(array_filter($models, static fn (mixed $name): bool => is_string($name) && strlen($name) <= 200)));
        natcasesort($models);

        return array_values($models);
    }

    private function request(string $method, string $url, #[\SensitiveParameter] array $options = []): array
    {
        try {
            return $this->http->request($method, $url, $options + ['timeout' => 8, 'max_duration' => 10, 'max_redirects' => 0])->toArray();
        } catch (\Throwable) {
            throw new \DomainException('Could not read models from this provider. Check its endpoint and credentials.');
        }
    }
}
