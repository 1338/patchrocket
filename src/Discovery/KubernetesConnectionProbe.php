<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Secrets\ConnectionCredentials;
use App\Secrets\SecretManagers;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class KubernetesConnectionProbe
{
    private const WORKLOADS = [
        'deployments' => 'apps',
        'statefulsets' => 'apps',
        'daemonsets' => 'apps',
        'replicasets' => 'apps',
        'pods' => '',
    ];
    private const ACCESS_API = 'authorization.k8s.io/v1';

    public function __construct(
        private readonly ConnectionCredentials $credentials,
        private readonly SecretManagers $managers,
        private readonly Repository $scratch,
    ) {
    }

    /** @return array{contexts: list<string>, currentContext: ?string} */
    public function contexts(array $selection): array
    {
        if ('managed' === $this->credentialMode($selection)) {
            $bundle = $this->managers->bundle($this->reference($selection));
            $kubeconfig = $bundle['kubeconfig'] ?? null;
            if (!is_string($kubeconfig) || '' === trim($kubeconfig)) {
                throw new \DomainException('Listing managed contexts requires a bundle containing a kubeconfig.');
            }
            try {
                $config = Yaml::parse($kubeconfig, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE, maxNestingLevel: 20);
            } catch (ParseException) {
                throw new \DomainException('The managed kubeconfig is not valid YAML.');
            }
        } else {
            $config = $this->workerConfig(['config', 'view', '-o', 'json']);
        }
        if (!is_array($config) || 'Config' !== ($config['kind'] ?? null) || !is_array($config['contexts'] ?? [])) {
            throw new \DomainException('Could not read kubeconfig contexts.');
        }

        $contexts = [];
        foreach ($config['contexts'] ?? [] as $entry) {
            $name = $entry['name'] ?? null;
            if (self::validContext($name)) {
                $contexts[] = $name;
            }
        }
        $contexts = array_values(array_unique($contexts));
        sort($contexts, SORT_STRING);
        $current = $config['current-context'] ?? null;

        return ['contexts' => $contexts, 'currentContext' => in_array($current, $contexts, true) ? $current : null];
    }

    /**
     * @return array{endpoint: string, reachable: ?bool, authenticated: ?bool, passed: bool,
     *     permissions: list<array{verb: string, resource: string, namespace: ?string, allowed: ?bool, label: string}>, message: string}
     */
    public function test(array $selection): array
    {
        return $this->withConfig($selection, $this->report(...));
    }

    /** @return array{namespaces: list<string>, namespaceCount: int, namespaceQuery?: string} */
    public function availableNamespaces(array $selection): array
    {
        $query = $selection['namespaceQuery'] ?? '';

        return $this->withConfig(array_replace($selection, ['namespaceMode' => 'all']), function (string $path, string $context) use ($query): array {
            $response = $this->kubectl([
                '--kubeconfig='.$path, '--context='.$context, '--cache-dir='.dirname($path).'/cache',
                '--request-timeout=5s', 'get', 'namespaces', '-o', 'jsonpath={.items[*].metadata.name}',
            ]);
            if (!$response?->isSuccessful()) {
                throw new \DomainException('The worker could not list namespaces. Enter the authorized namespace names manually.');
            }
            $names = preg_split('/\s+/', trim($response->getOutput()), flags: PREG_SPLIT_NO_EMPTY) ?: [];
            if ('' !== $query) {
                $names = array_values(array_filter($names, static fn (string $name): bool => str_contains($name, $query)));
            }
            sort($names, SORT_STRING);

            return ['namespaces' => array_slice($names, 0, 500), 'namespaceCount' => count($names)]
                + ('' === $query ? [] : ['namespaceQuery' => $query]);
        });
    }

    /**
     * Recheck immediately before discovery and pass the same scoped kubeconfig to the callback.
     * The file remains available only for the duration of the callback.
     *
     * @template T
     * @param callable(string): T $discover
     * @return T
     */
    public function withVerifiedConnection(array $selection, callable $discover): mixed
    {
        return $this->withConfig($selection, function (string $path, string $context, array $namespaces) use ($discover): mixed {
            $report = $this->report($path, $context, $namespaces);
            if (!$report['passed']) {
                throw new \DomainException($report['message']);
            }

            return $discover($path);
        });
    }

    private function withConfig(array $selection, callable $operation): mixed
    {
        $context = $selection['target'] ?? null;
        if (!self::validContext($context)) {
            throw new \DomainException('Choose a valid kubeconfig context.');
        }
        $namespaces = $this->namespaces($selection);
        if ('managed' === $this->credentialMode($selection)) {
            try {
                return $this->credentials->kubernetes(
                    $this->reference($selection), $context, function (string $path) use ($operation, $context, $namespaces): mixed {
                        $this->scopeManagedConfig($path, $context);

                        return $operation($path, $context, $namespaces);
                    },
                );
            } catch (ParseException) {
                throw new \DomainException('The managed kubeconfig is not valid YAML.');
            }
        }

        $config = $this->workerConfig(['--context='.$context, 'config', 'view', '--minify', '--flatten', '--raw', '-o', 'json']);
        if (($config['current-context'] ?? null) !== $context) {
            throw new \DomainException('The worker kubeconfig must include the selected context.');
        }

        return $this->scratch->temporary(function (string $root) use ($config, $context, $namespaces, $operation): mixed {
            $path = $root.'/kubeconfig';
            $this->writeConfig($path, $config);

            return $operation($path, $context, $namespaces);
        });
    }

    private function scopeManagedConfig(string $path, string $name): void
    {
        $config = json_decode((string) @file_get_contents($path), true);
        $context = self::entries($config, 'contexts', 'context')[$name] ?? null;
        $clusterName = $context['cluster'] ?? null;
        $userName = $context['user'] ?? null;
        $cluster = is_string($clusterName) ? (self::entries($config, 'clusters', 'cluster')[$clusterName] ?? null) : null;
        $user = is_string($userName) ? (self::entries($config, 'users', 'user')[$userName] ?? null) : null;
        if (!is_array($cluster) || !is_array($user)) {
            throw new \DomainException('The selected managed context must reference a cluster and inline credentials.');
        }

        // Hand kubectl only the canonical fields covered by managed credential validation.
        $this->writeConfig($path, [
            'apiVersion' => 'v1', 'kind' => 'Config', 'current-context' => $name,
            'contexts' => [['name' => $name, 'context' => array_intersect_key($context, array_flip(['cluster', 'user', 'namespace']))]],
            'clusters' => [['name' => $clusterName, 'cluster' => $cluster]],
            'users' => [['name' => $userName, 'user' => $user]],
        ]);
    }

    private function writeConfig(string $path, #[\SensitiveParameter] array $config): void
    {
        if (false === @file_put_contents($path, json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)) || !@chmod($path, 0600)) {
            throw new \DomainException('Could not prepare a private kubeconfig.');
        }
    }

    private function report(string $path, string $context, array $namespaces): array
    {
        $config = json_decode((string) @file_get_contents($path), true);
        $endpoint = $this->endpoint($config, $context);
        $base = ['--kubeconfig='.$path, '--context='.$context, '--cache-dir='.dirname($path).'/cache', '--request-timeout=5s'];
        $identity = $this->kubectl([...$base, 'auth', 'whoami', '-o', 'json'], timeout: 10);
        [$reachable, $authenticated] = $this->authentication($identity);

        $permissions = [];
        $passed = true === $authenticated;
        $deadline = hrtime(true) + 35_000_000_000;
        foreach ($namespaces as $namespace) {
            $resources = null === $namespace ? ['namespaces' => ''] + self::WORKLOADS : self::WORKLOADS;
            foreach ($resources as $resource => $group) {
                $remaining = ($deadline - hrtime(true)) / 1_000_000_000;
                $allowed = true === $authenticated && $remaining > 0
                    ? $this->permission($base, $resource, $group, $namespace, min(7, $remaining))
                    : null;
                $qualified = '' === $group ? $resource : $resource.'.'.$group;
                $scope = $namespace ?? ('namespaces' === $resource ? 'cluster-wide' : 'all namespaces');
                $permissions[] = [
                    'verb' => 'list', 'resource' => $qualified, 'namespace' => $namespace, 'allowed' => $allowed,
                    'label' => 'list · '.$qualified.' · '.$scope,
                ];
                $passed = $passed && true === $allowed;
            }
        }
        $message = match (true) {
            $passed => 'The Kubernetes identity has the required inventory permissions.',
            false === $reachable => 'The worker could not reach the Kubernetes API. Check worker connectivity and TLS settings.',
            false === $authenticated => 'The Kubernetes API did not authenticate the selected credentials.',
            null === $authenticated => 'The worker could not verify its Kubernetes identity. Check kubectl, credentials, and access to SelfSubjectReview.',
            default => 'The worker could not confirm all required Kubernetes list permissions.',
        };

        return compact('endpoint', 'reachable', 'authenticated', 'passed', 'permissions', 'message');
    }

    private function endpoint(#[\SensitiveParameter] mixed $config, string $context): string
    {
        $contexts = self::entries($config, 'contexts', 'context');
        $clusters = self::entries($config, 'clusters', 'cluster');
        $cluster = $contexts[$context]['cluster'] ?? null;
        $server = is_string($cluster) ? ($clusters[$cluster]['server'] ?? null) : null;
        $url = is_string($server) ? parse_url($server) : false;
        $host = $url['host'] ?? '';
        if (!in_array($url['scheme'] ?? '', ['https', 'http'], true)
            || (!preg_match('/^[a-zA-Z0-9.-]+$/D', $host) && !filter_var(trim($host, '[]'), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))) {
            throw new \DomainException('The selected context must reference a valid Kubernetes API endpoint.');
        }

        // Display only the origin. Worker URLs can contain private routing paths or credentials.
        return $url['scheme'].'://'.$host.(isset($url['port']) ? ':'.$url['port'] : '');
    }

    private static function entries(#[\SensitiveParameter] mixed $config, string $section, string $field): array
    {
        $entries = $config[$section] ?? null;

        return is_array($entries) ? array_column($entries, $field, 'name') : [];
    }

    /** @return array{?bool, ?bool} */
    private function authentication(?Process $response): array
    {
        if ($response?->isSuccessful()) {
            $review = json_decode($response->getOutput(), true);
            $identity = $review['status']['userInfo'] ?? [];
            $name = $identity['username'] ?? null;
            if ('SelfSubjectReview' !== ($review['kind'] ?? null) || !is_string($name) || '' === trim($name)) {
                return [true, null];
            }
            $groups = $identity['groups'] ?? [];

            return [true, 'system:anonymous' !== $name && is_array($groups) && !in_array('system:unauthenticated', $groups, true)];
        }

        $error = $response?->getErrorOutput() ?? '';
        if (preg_match('/^(?:error: You must be logged in to the server|Error from server \(Unauthorized\):)/m', $error)) {
            return [true, false];
        }
        if (preg_match('/^(?:Error from server \([a-zA-Z]+\):|error: the selfsubjectreviews API is not enabled in the cluster)/m', $error)) {
            return [true, null];
        }
        if (preg_match('/^(?:Unable to connect to the server:|The connection to the server .* was refused)/m', $error)) {
            return [false, null];
        }

        return [null, null];
    }

    private function permission(array $base, string $resource, string $group, ?string $namespace, float $timeout): ?bool
    {
        $attributes = ['verb' => 'list', 'resource' => $resource, 'group' => $group];
        if (null !== $namespace) {
            $attributes['namespace'] = $namespace;
        }
        // A SelfSubjectAccessReview is a virtual API resource. The POST evaluates authorization without storing an object.
        $request = json_encode([
            'apiVersion' => self::ACCESS_API, 'kind' => 'SelfSubjectAccessReview',
            'spec' => ['resourceAttributes' => $attributes],
        ], JSON_THROW_ON_ERROR);
        $response = $this->kubectl([...$base, 'create', '--raw=/apis/'.self::ACCESS_API.'/selfsubjectaccessreviews', '-f', '-'], $request, $timeout);
        if (!$response?->isSuccessful()) {
            return null;
        }
        $review = json_decode($response->getOutput(), true);
        $status = $review['status'] ?? [];
        if ('SelfSubjectAccessReview' !== ($review['kind'] ?? null) || !empty($status['evaluationError'])) {
            return null;
        }

        $allowed = $status['allowed'] ?? null;

        return is_bool($allowed) ? $allowed : null;
    }

    private function workerConfig(array $args): array
    {
        $process = $this->kubectl($args);
        $config = $process?->isSuccessful() ? json_decode($process->getOutput(), true) : null;
        if (!is_array($config) || 'Config' !== ($config['kind'] ?? null)) {
            throw new \DomainException('Could not read the selected worker kubeconfig. Check that kubectl and the worker configuration are available.');
        }

        return $config;
    }

    private function kubectl(array $args, ?string $input = null, float $timeout = 10): ?Process
    {
        try {
            $process = new Process(['kubectl', ...$args], env: ['KUBECTL_KUBERC' => 'false'], input: $input, timeout: $timeout);
            $bytes = 0;
            $process->run(static function (string $type, string $chunk) use (&$bytes): void {
                $bytes += strlen($chunk);
                if ($bytes > 4_194_304) {
                    throw new RuntimeException('The kubectl response exceeded its size limit.');
                }
            });

            return $process;
        } catch (ExceptionInterface) {
            // CLI diagnostics and auth plugin output can contain credentials.
            return null;
        }
    }

    private function credentialMode(array $selection): string
    {
        $mode = $selection['credentialMode'] ?? null;
        if (!in_array($mode, ['worker', 'managed'], true)) {
            throw new \DomainException('Choose a credential source.');
        }

        return $mode;
    }

    private function reference(array $selection): string
    {
        $reference = $selection['credential'] ?? null;
        if (!is_string($reference) || !SecretManagers::validReference($reference)) {
            throw new \DomainException('Enter a managed kubeconfig reference.');
        }

        return $reference;
    }

    /** @return list<?string> */
    private function namespaces(array $selection): array
    {
        if ('all' === ($selection['namespaceMode'] ?? null)) {
            return [null];
        }
        $namespaces = $selection['namespaces'] ?? null;
        if ('selected' !== ($selection['namespaceMode'] ?? null) || !is_array($namespaces) || !array_is_list($namespaces)
            || !$namespaces || count($namespaces) > 20) {
            throw new \DomainException('Choose all namespaces or enter up to 20 namespace names.');
        }
        foreach ($namespaces as $namespace) {
            if (!is_string($namespace) || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
                throw new \DomainException('Enter valid Kubernetes namespace names.');
            }
        }

        return array_values(array_unique($namespaces));
    }

    private static function validContext(mixed $name): bool
    {
        return is_string($name) && '' !== $name && trim($name) === $name && strlen($name) <= 253 && !preg_match('/[\x00-\x1f\x7f]/', $name);
    }
}
