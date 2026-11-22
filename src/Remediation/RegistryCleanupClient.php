<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Secrets\SecretManagers;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class RegistryCleanupClient
{
    public function __construct(private readonly HttpClientInterface $http, private readonly SecretManagers $secrets)
    {
    }

    public function endpoint(array $image, string $provider): string
    {
        [$host, $repository, $digest] = $image;
        if ('harbor' === $provider) {
            [$project, $name] = explode('/', $repository, 2) + [1 => ''];
            if ('' === $name) {
                throw new \DomainException('A Harbor artifact needs a project and repository.');
            }

            return "https://$host/api/v2.0/projects/".rawurlencode($project).'/repositories/'.rawurlencode(rawurlencode($name)).'/artifacts/'.rawurlencode($digest);
        }

        return "https://$host/v2/$repository/manifests/$digest";
    }

    public function request(string $method, string $url, string $reference): int
    {
        return $this->exchange($method, $url, $reference)['status'];
    }

    public function referencesDigest(array $image, array $settings, string $reference, string $digest): bool
    {
        $image[2] = $reference;
        [$resolved, $children] = $this->manifest($image, $settings);

        return $resolved === $digest || in_array($digest, $children, true);
    }

    public function confirm(array $image, array $settings): array
    {
        [$resolved, $children] = $this->manifest($image, $settings);
        if ($image[2] !== $resolved) {
            throw new \DomainException('The registry did not confirm the exact approved digest.');
        }

        return $children;
    }

    private function manifest(array $image, array $settings): array
    {
        $result = $this->exchange('GET', $this->endpoint($image, $settings['provider']), $settings['credential'], true);
        if (200 !== $result['status']) {
            throw new \DomainException('The worker could not resolve an image reference in the registry.');
        }
        $artifact = json_decode($result['body'], true);
        $resolved = 'harbor' === $settings['provider']
            ? ($artifact['digest'] ?? null)
            : ($result['headers']['docker-content-digest'][0] ?? null);
        if (!is_string($resolved) || !preg_match('/^sha256:[a-f0-9]{64}$/D', $resolved) || !is_array($artifact)) {
            throw new \DomainException('The registry did not return a verifiable manifest for a deployment image.');
        }
        $children = 'harbor' === $settings['provider']
            ? array_column($artifact['references'] ?? [], 'child_digest')
            : array_column($artifact['manifests'] ?? [], 'digest');

        return [$resolved, $children];
    }

    private function exchange(string $method, string $url, string $reference, bool $read = false): array
    {
        $secret = $this->secrets->bundle($reference);
        $options = ['max_redirects' => 0, 'timeout' => 15, 'max_duration' => 25, 'headers' => [
            'Accept' => 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/json',
        ]];
        if (is_string($secret['bearer_token'] ?? null) && preg_match('/^[a-zA-Z0-9._~+\/=\-]+$/D', $secret['bearer_token'])) {
            $options['auth_bearer'] = $secret['bearer_token'];
        } elseif (is_string($secret['username'] ?? null) && is_string($secret['token'] ?? null)
            && $secret['username'] !== '' && $secret['token'] !== '' && !str_contains($secret['username'], ':')) {
            $options['auth_basic'] = [$secret['username'], $secret['token']];
        } else {
            throw new \DomainException('The cleanup credential needs a registry username and token or a bearer token.');
        }
        try {
            $response = $this->http->request($method, $url, $options);
            $status = $response->getStatusCode();
            $headers = $response->getHeaders(false);
            $body = $read && 200 === $status ? $response->getContent(false) : '';
            $response->cancel();

            return compact('status', 'headers', 'body');
        } catch (ExceptionInterface) {
            throw new \DomainException('The registry request failed. Check registry access and worker connectivity.');
        }
    }
}
