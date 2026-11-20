<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Audit\Store;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;

final class DeliveryDiscovery
{
    public const TYPES = [
        'jenkins' => 'Jenkins', 'harbor' => 'Harbor', 'argocd' => 'Argo CD', 'registry' => 'Registry',
        'vm' => 'Linux host', 'cluster' => 'Kubernetes cluster',
        'gitlab' => 'GitLab', 'flux' => 'Flux', 'github-runner' => 'GitHub Actions runner',
    ];

    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly JenkinsConnections $jenkins,
        private readonly OperatorSettings $operator,
    ) {
    }

    public function record(string $source, array $candidates): int
    {
        if ('' === $source || strlen($source) > 512 || preg_match('/[\x00-\x1f\x7f]/', $source)) {
            throw new \DomainException('Choose a valid discovery scope.');
        }

        $observed = [];
        foreach ($candidates as $candidate) {
            $normalized = self::normalize($candidate);
            if (null !== $normalized) {
                $observed[$normalized['id']] = $normalized;
            }
        }

        $this->store->put('operator_settings', [
            'id' => 'delivery-source:'.substr(hash('sha256', $source), 0, 48),
            'data' => Store::json(['source' => $source, 'observed_at' => gmdate(DATE_ATOM), 'candidates' => array_values($observed)]),
        ]);

        return count($observed);
    }

    public function all(): array
    {
        $bindings = [];
        foreach ($this->store->rows("SELECT data FROM operator_settings WHERE id LIKE 'delivery-binding:%'") as $row) {
            $bindings[$row['data']['candidate']] = $row['data'];
        }

        $candidates = [];
        foreach ($this->store->iterate("SELECT data FROM operator_settings WHERE id LIKE 'delivery-source:%' ORDER BY id") as $row) {
            $report = $row['data'];
            foreach ($report['candidates'] as $candidate) {
                $id = $candidate['id'];
                $candidates[$id] ??= $candidate + ['sources' => [], 'cluster_sources' => [], 'binding' => $bindings[$id] ?? null];
                $candidates[$id]['sources'][$report['source']] = $report['observed_at'];
                if ($candidate['connection_id'] && $candidate['namespace']) {
                    $candidates[$id]['cluster_sources'][$candidate['connection_id']] = $candidate['namespace'];
                }
            }
        }
        uasort($candidates, static fn (array $a, array $b): int => [$a['kind'], $a['endpoint'], $a['id']] <=> [$b['kind'], $b['endpoint'], $b['id']]);

        return $candidates;
    }

    public function adopt(string $id, array $input): void
    {
        $candidate = $this->all()[$id] ?? throw new \DomainException('This discovery result is no longer available. Run discovery again.');
        $reference = trim($input['reference'] ?? '');
        $target = trim($input['endpoint'] ?? '');
        if ('' !== $reference && !SecretManagers::validReference($reference)) {
            throw new \DomainException('Enter a managed credential reference in manager:secret format.');
        }

        $this->store->db->transactional(function () use ($candidate, $id, $input, $reference, $target): void {
            $binding = ['candidate' => $id, 'target' => $target];
            switch ($candidate['kind']) {
                case 'jenkins':
                    if ('' === $reference) {
                        throw new \DomainException('Enter the managed Jenkins read credential reference.');
                    }
                    $this->jenkins->save($target, $reference);
                    break;
                case 'harbor':
                case 'registry':
                    if ('' === $reference) {
                        throw new \DomainException('Enter the managed registry pull credential reference.');
                    }
                    $this->operator->saveRegistryReference($target, $reference);
                    break;
                case 'argocd':
                    $namespace = trim($input['namespace'] ?? '');
                    if ('' === $namespace) {
                        throw new \DomainException('Enter the namespace where Argo CD Applications are registered.');
                    }
                    $choice = $this->connectArgo(trim($input['cluster'] ?? ''), $namespace, $reference);
                    $binding['target'] = $choice['name'].' / '.$namespace;
                    $binding['connection_id'] = $choice['id'];
                    break;
                case 'vm':
                case 'cluster':
                    $binding['connection_id'] = $this->connectInfrastructure($candidate, $target, $reference, trim($input['namespace'] ?? ''));
                    break;
                default:
                    throw new \DomainException('This service is available as discovery evidence.');
            }

            $this->store->put('operator_settings', [
                'id' => 'delivery-binding:'.substr($id, 0, 47),
                'data' => Store::json($binding),
            ]);
        });
    }

    private function connectArgo(string $id, string $namespace, string $reference): array
    {
        $cluster = $this->connections->get($id);
        if ('cluster' !== ($cluster['kind'] ?? null) || ('' === ($cluster['data']['credential'] ?? '') && '' === $reference)) {
            throw new \DomainException('Choose a managed Kubernetes connection or enter an Argo CD credential reference.');
        }
        $data = $cluster['data'];
        $existingNamespace = $data['argo_namespace'] ?? '';
        if ('' !== $existingNamespace && $namespace !== $existingNamespace) {
            foreach ($this->connections->all() as $option) {
                if ('cluster' === $option['kind'] && ($option['data']['target'] ?? '') === $data['target']
                    && ($option['data']['credential'] ?? '') === ($data['credential'] ?? '')
                    && ($option['data']['argo_namespace'] ?? '') === $namespace) {
                    $cluster = $option;
                    break;
                }
            }
            if ($cluster['id'] === $id) {
                $name = substr($cluster['name'], 0, 55).' / '.$namespace;
                $clone = array_intersect_key($data, array_flip([
                    'target', 'namespace', 'repository', 'all_namespaces', 'registries', 'platform', 'host_asset', 'credential',
                ]));
                $clone['credential'] = ($clone['credential'] ?? '') ?: $reference;
                $clone['argo_namespace'] = $namespace;

                $newId = $this->connections->save('cluster', ['name' => $name, 'interval' => '0'] + $clone);
                $cluster = $this->connections->get($newId);
            }
        }

        $this->connections->saveArgo($cluster['id'], $namespace, $reference ?: ($cluster['data']['argo_credential'] ?? ''));

        return $cluster;
    }

    private function connectInfrastructure(array $candidate, string $target, string $reference, string $namespace): string
    {
        $kind = $candidate['kind'];
        $namespace = '' !== $namespace ? $namespace : 'default';
        if ('cluster' === $kind && !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
            throw new \DomainException('Enter a valid Kubernetes namespace.');
        }
        foreach ($this->connections->all() as $connection) {
            $data = $connection['data'];
            if ($kind === $connection['kind'] && $target === $data['target'] && $reference === ($data['credential'] ?? '')
                && ('vm' === $kind || $namespace === ($data['namespace'] ?: 'default'))) {
                return $connection['id'];
            }
        }

        return $this->connections->save($kind, [
            'name' => substr($candidate['label'], 0, 120), 'target' => $target, 'credential' => $reference,
            'namespace' => $namespace, 'platform' => 'linux/amd64', 'interval' => '0',
        ]);
    }

    private static function normalize(array $candidate): ?array
    {
        $kind = self::field($candidate, 'kind', 32);
        $endpoint = self::endpoint(self::field($candidate, 'endpoint', 512));
        if (!isset(self::TYPES[$kind]) || null === $endpoint) {
            return null;
        }
        $namespace = self::field($candidate, 'namespace', 63);
        $connection = self::field($candidate, 'connection_id', 64);
        $resource = self::field($candidate, 'resource_id', 512);
        if (str_contains($endpoint, '.svc') || ('argocd' === $kind && '' !== $namespace) || in_array($kind, ['vm', 'cluster'], true)) {
            $identityScope = $resource ?: "$connection/$namespace";
        } else {
            $identityScope = '';
        }

        return [
            'id' => hash('sha256', "$kind/$endpoint/$identityScope"), 'kind' => $kind, 'endpoint' => $endpoint,
            'label' => self::field($candidate, 'label', 512) ?: $endpoint,
            'namespace' => $namespace, 'connection_id' => $connection,
            'evidence' => self::field($candidate, 'evidence', 160),
        ];
    }

    private static function field(array $data, string $name, int $limit): string
    {
        $value = $data[$name] ?? '';

        return is_string($value) && strlen($value) <= $limit && !preg_match('/[\x00-\x1f\x7f]/', $value) ? trim($value) : '';
    }

    private static function endpoint(string $endpoint): ?string
    {
        $endpoint = trim($endpoint);
        if ('' === $endpoint || strlen($endpoint) > 512 || preg_match('~[\x00-\x20\x7f\\\\]~', $endpoint)) {
            return null;
        }
        $url = parse_url(str_contains($endpoint, '://') ? $endpoint : '//'.$endpoint);
        if (!is_array($url) || array_diff(array_keys($url), ['scheme', 'host', 'port', 'path'])) {
            return null;
        }
        $host = strtolower($url['host'] ?? '');
        $scheme = strtolower($url['scheme'] ?? '');
        $path = rtrim($url['path'] ?? '', '/');
        if ((!preg_match('/^[a-z0-9][a-z0-9.-]*$/D', $host) && !filter_var(trim($host, '[]'), FILTER_VALIDATE_IP))
            || !in_array($scheme, ['', 'https', 'http'], true) || ('' === $scheme && '' !== $path)) {
            return null;
        }
        $port = $url['port'] ?? null;
        if (('https' === $scheme && 443 === $port) || ('http' === $scheme && 80 === $port)) {
            $port = null;
        }

        return ('' !== $scheme ? $scheme.'://' : '').$host.(null !== $port ? ':'.$port : '').$path;
    }
}
