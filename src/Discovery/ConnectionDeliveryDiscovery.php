<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Secrets\ConnectionCredentials;
use App\Settings\Connections;

final class ConnectionDeliveryDiscovery
{
    public function __construct(
        private readonly HostCollector $hosts,
        private readonly Infrastructure $kube,
        private readonly ConnectionCredentials $credentials,
        private readonly DeliveryDiscovery $discovery,
    ) {
    }

    public function discover(array $connection): string
    {
        $data = $connection['data'];
        $target = $data['target'];
        $warnings = [];
        if ('vm' === $connection['kind']) {
            $records = $this->credentials->ssh($data['credential'], fn (array $options): array => $this->hosts->deliveryServices(
                $target, $options, !empty($data['docker_inventory']), !empty($data['docker_sudo']),
            ), ($data['port'] ?? '') ?: null);
            if (!in_array(['probe', 'systemd'], $records, true) && !in_array(['probe', 'docker'], $records, true)) {
                throw new \DomainException('The SSH connection could not read running systemd units or Docker container metadata.');
            }
            $host = substr($target, strpos($target, '@') + 1);
            $candidates = self::fromHost($host, $records);
            $warnings = array_values(array_intersect(
                array_column(array_filter($records, static fn (array $record): bool => 'warning' === ($record[0] ?? null)), 1),
                ['Systemd metadata was unavailable', 'Docker metadata was unavailable'],
            ));
            $scope = 'SSH · '.$host.(!empty($data['port']) ? ':'.$data['port'] : '');
        } else {
            $namespace = ($data['namespace'] ?? '') ?: 'default';
            $all = !empty($data['all_namespaces']);
            $resources = $this->credentials->kubernetes($data['credential'], $target, fn (string $config): array =>
                $this->kube->deliveryResources($target, $namespace, $all, $config));
            $argoNamespace = $data['argo_namespace'] ?? '';
            if ('' !== $argoNamespace) {
                try {
                    $apps = $this->credentials->kubernetes(Connections::argoCredential($data), $target, fn (string $config): array =>
                        $this->kube->argoApplications($target, $argoNamespace, $config));
                    $resources['applications.argoproj.io'] = [...($resources['applications.argoproj.io'] ?? []), ...$apps];
                } catch (\DomainException) {
                    $warnings[] = 'Could not read the configured Argo CD Applications namespace.';
                }
            }
            if (count(array_filter($resources, 'is_array')) === 0) {
                throw new \DomainException('The Kubernetes identity could not list Services, Ingresses, Deployments, or Argo CD Applications in this scope.');
            }
            $missing = array_keys(array_filter($resources, static fn (?array $records): bool => null === $records));
            if ($missing) {
                $warnings[] = 'Unavailable resource lists: '.implode(', ', $missing).'.';
            }
            $candidates = self::fromKubernetes($resources, $target, $connection['id']);
            $scope = 'Kubernetes · '.$target.' / '.($all ? 'all namespaces' : $namespace);
        }

        $count = $this->discovery->record($scope, $candidates);

        return sprintf('%d discovery candidate(s).', $count).($warnings ? ' '.implode(' ', $warnings) : '');
    }

    public static function fromHost(string $host, array $records): array
    {
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '['.$host.']';
        }
        $candidates = [];
        $dockerKinds = [];
        foreach ($records as $record) {
            if ('docker' !== ($record[0] ?? '') || count($record) < 3) {
                continue;
            }
            [, $name, $image] = $record;
            if (!($kind = self::resourceKind(['name' => $name]) ?? self::imageKind($image))) {
                continue;
            }
            $dockerKinds[$kind] = true;
            $endpoints = [];
            preg_match_all('/(?:^|,\s*)(\S+):(\d{1,5})->(\d{1,5})\/tcp/', $record[3] ?? '', $matches, PREG_SET_ORDER);
            foreach ($matches as [, $address, $published, $port]) {
                if (in_array($address, ['127.0.0.1', '[::1]', '::1'], true)
                    || ('jenkins' === $kind && '50000' === $port)) {
                    continue;
                }
                $scheme = in_array((int) $port, [443, 8443], true) ? 'https' : 'http';
                $endpoints[] = $scheme.'://'.$host.':'.$published;
            }
            foreach (array_unique($endpoints ?: [$host]) as $endpoint) {
                $candidates[] = ['kind' => $kind, 'endpoint' => $endpoint, 'label' => $name, 'evidence' => 'Running Docker container'];
            }
        }

        foreach ($records as $record) {
            if ('service' !== ($record[0] ?? '') || !($kind = self::kind($record[1] ?? '')) || isset($dockerKinds[$kind])) {
                continue;
            }
            $candidates[] = ['kind' => $kind, 'endpoint' => $host, 'label' => $record[1], 'evidence' => 'Running systemd unit'];
        }

        return $candidates;
    }

    public static function fromKubernetes(array $resources, string $context, string $connectionId): array
    {
        $services = [];
        foreach ($resources['services'] ?? [] as $service) {
            $meta = $service['metadata'] ?? [];
            if ($kind = self::resourceKind($meta)) {
                $services[($meta['namespace'] ?? 'default').'/'.($meta['name'] ?? '')] = ['kind' => $kind, 'service' => $service];
            }
        }

        $candidates = [];
        $external = [];
        $seen = [];
        $candidate = static function (string $kind, string $namespace, string $name, string $endpoint, string $evidence) use ($context, $connectionId, &$seen): array {
            $seen[$namespace][$kind] = true;

            return [
                'kind' => $kind, 'endpoint' => $endpoint, 'label' => $name, 'namespace' => $namespace,
                'resource_id' => $context.'/'.$namespace, 'connection_id' => $connectionId, 'evidence' => $evidence,
            ];
        };
        foreach ($resources['ingresses.networking.k8s.io'] ?? [] as $ingress) {
            $meta = $ingress['metadata'] ?? [];
            $name = $meta['name'] ?? '';
            $namespace = $meta['namespace'] ?? 'default';
            $tlsHosts = array_merge([], ...array_column($ingress['spec']['tls'] ?? [], 'hosts'));
            foreach ($ingress['spec']['rules'] ?? [] as $rule) {
                $host = $rule['host'] ?? '';
                if ('' === $host || str_contains($host, '*')) {
                    continue;
                }
                $scheme = in_array($host, $tlsHosts, true) ? 'https' : 'http';
                foreach ($rule['http']['paths'] ?? [] as $path) {
                    $service = $path['backend']['service']['name'] ?? '';
                    $key = $namespace.'/'.$service;
                    $kind = $services[$key]['kind'] ?? self::kind($service) ?? self::resourceKind($meta);
                    if (null === $kind) {
                        continue;
                    }
                    $prefix = $path['path'] ?? '';
                    if (!preg_match('~^(/[a-zA-Z0-9._/-]*)?$~D', $prefix)) {
                        $prefix = '';
                    }
                    $candidates[] = $candidate($kind, $namespace, $name, $scheme.'://'.$host.$prefix, 'Kubernetes Ingress');
                    $external[$key] = true;
                }
            }
        }

        foreach ($services as $key => $item) {
            if (isset($external[$key])) {
                continue;
            }
            [$namespace, $name] = explode('/', $key, 2);
            $service = $item['service'];
            $backends = $service['status']['loadBalancer']['ingress'] ?? [];
            $endpoint = $name.'.'.$namespace.'.svc';
            $evidence = 'Kubernetes Service';
            foreach ($backends as $backend) {
                if ($host = $backend['hostname'] ?? $backend['ip'] ?? '') {
                    if (str_contains($host, ':') && !str_starts_with($host, '[')) {
                        $host = '['.$host.']';
                    }
                    $ports = [];
                    foreach ($service['spec']['ports'] ?? [] as $port) {
                        $number = $port['port'] ?? 0;
                        $portName = $port['name'] ?? '';
                        if (str_starts_with($portName, 'http') || in_array($number, [80, 443, 5000, 8080, 8443], true)) {
                            $scheme = str_contains($portName, 'https') || in_array($number, [443, 8443], true) ? 'https' : 'http';
                            $ports[] = $scheme.'://'.$host.':'.$number;
                        }
                    }
                    foreach ($ports ?: [$host] as $endpoint) {
                        $candidates[] = $candidate($item['kind'], $namespace, $name, $endpoint, 'Kubernetes LoadBalancer Service');
                    }
                }
            }
            if (!$backends) {
                $candidates[] = $candidate($item['kind'], $namespace, $name, $endpoint, $evidence);
            }
        }

        foreach ($resources['deployments'] ?? [] as $deployment) {
            $meta = $deployment['metadata'] ?? [];
            $name = $meta['name'] ?? '';
            $namespace = $meta['namespace'] ?? 'default';
            $kind = self::resourceKind($meta);
            if (null === $kind) {
                foreach ($deployment['spec']['template']['spec']['containers'] ?? [] as $container) {
                    if ($kind = self::imageKind($container['image'] ?? '')) {
                        break;
                    }
                }
            }
            if ($kind && !isset($seen[$namespace][$kind])) {
                $candidates[] = $candidate($kind, $namespace, $name, $name.'.'.$namespace.'.svc', 'Kubernetes Deployment');
            }
        }

        foreach ($resources['applications.argoproj.io'] ?? [] as $application) {
            $namespace = $application['metadata']['namespace'] ?? '';
            if ('' !== $namespace && !isset($seen[$namespace]['argocd'])) {
                $candidates[] = $candidate('argocd', $namespace, 'Argo CD / '.$namespace, $namespace.'.svc', 'Argo CD Applications');
            }
        }

        return $candidates;
    }

    private static function resourceKind(array $metadata): ?string
    {
        $name = $metadata['name'] ?? '';
        if (preg_match('/(?:^|[-_.])(?:agent|controller|repo-server|redis|notifier|notifications|dex|exporter|database|db|jobservice|trivy)(?:$|[-_.])/', $name)) {
            return null;
        }

        return self::kind($name) ?? self::kind($metadata['labels']['app.kubernetes.io/name'] ?? '')
            ?? self::kind($metadata['labels']['app.kubernetes.io/instance'] ?? '');
    }

    private static function imageKind(string $image): ?string
    {
        $image = strtolower($image);
        foreach (['jenkins/jenkins' => 'jenkins', 'goharbor/harbor-core' => 'harbor', 'goharbor/nginx-photon' => 'harbor',
            'goharbor/harbor-portal' => 'harbor', 'argoproj/argocd' => 'argocd',
            'gitlab/gitlab-' => 'gitlab', 'fluxcd/' => 'flux', 'actions-runner' => 'github-runner'] as $marker => $kind) {
            if (str_contains($image, $marker)) {
                return $kind;
            }
        }

        return preg_match('~(?:^|/)registry(?:$|[:@])~', $image) ? 'registry' : null;
    }

    private static function kind(string $name): ?string
    {
        $name = strtolower($name);
        foreach (['jenkins' => 'jenkins', 'argo-?cd' => 'argocd', 'harbor' => 'harbor', 'gitlab' => 'gitlab', 'flux' => 'flux',
            'actions-runner|github-runner' => 'github-runner', 'registry' => 'registry'] as $pattern => $kind) {
            if (preg_match('/(?:^|[-_.])(?:'.$pattern.')(?:$|[-_.])/', $name)) {
                return $kind;
            }
        }

        return null;
    }
}
