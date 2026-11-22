<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Asset\Inventory;
use App\Audit\Store;
use Symfony\Component\Process\Process;

final class Infrastructure
{
    public function __construct(private readonly Inventory $inventory, private readonly Store $store)
    {
    }

    public function docker(?string $label, ?string $repository, ?string $context = null): int
    {
        return $this->dockerInventory($label, $repository, $context)['containers'];
    }

    /** @return array{host: string, containers: int} */
    public function dockerInventory(?string $label, ?string $repository, ?string $context = null): array
    {
        $this->validateRepository($repository);
        $args = [...$this->dockerCommand($context), 'container', 'ls', '-aq', '--no-trunc'];
        if (null !== $label) {
            array_push($args, '--filter', 'label='.$label);
        }
        $dockerContext = $context ?? trim($this->run(['docker', 'context', 'show']));
        $matches = trim($this->run($args));
        $host = $this->inventory->asset('docker', $dockerContext, $dockerContext, ['scope' => $label]);
        $count = 0;
        foreach (preg_split('/\s+/', $matches, -1, PREG_SPLIT_NO_EMPTY) as $container) {
            $record = $this->inspectContainer($container, $context);
            $image = $this->dockerImage($record['image'], $record['reference'], $context);
            $containerId = $this->inventory->asset('container', $dockerContext.'/'.$container, $record['name'], [
                'container' => $container, 'context' => $dockerContext, 'image' => $record['image'],
                'running' => $record['running'], 'reference' => $record['reference'], 'health' => $record['health'],
            ]);
            $this->store->db->transactional(function () use ($host, $containerId, $image, $repository): void {
                $this->inventory->link($host, 'HOSTS', $containerId, 'Docker');
                $this->store->db->delete('asset_links', ['source_id' => $containerId, 'kind' => 'RUNS']);
                $this->inventory->link($containerId, 'RUNS', $image, 'Docker');
                if ($repository) {
                    $this->inventory->link($image, 'BUILT_FROM', $repository, 'Operator association');
                }
            });
            ++$count;
        }

        return ['host' => $host, 'containers' => $count];
    }

    public function inspectContainer(string $id, ?string $context = null): array
    {
        $format = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},"reference":{{json .Config.Image}},"health":{{json (index .State "Health")}},"healthcheck":{{with index .Config "Healthcheck"}}{{json (index . "Test")}}{{else}}null{{end}},"service":{{with index .Config "Labels"}}{{json (index . "org.patchrocket.service")}}{{else}}null{{end}}}';
        $data = json_decode($this->run([...$this->dockerCommand($context), 'container', 'inspect', '--format', $format, '--', $id]), true, flags: JSON_THROW_ON_ERROR);
        $data['name'] = ltrim($data['name'], '/');
        $data['health'] = $data['health']['Status'] ?? null;

        return $data;
    }

    public function inspectImage(string $reference, ?string $context = null): array
    {
        $format = '{"digest":{{json .Id}},"repo_digests":{{json .RepoDigests}},"labels":{{json (index .Config "Labels")}}}';
        $image = json_decode($this->run([...$this->dockerCommand($context), 'image', 'inspect', '--format', $format, '--', $reference]), true, flags: JSON_THROW_ON_ERROR);
        $labels = $image['labels'];

        return [
            'digest' => $image['digest'], 'repo_digests' => $image['repo_digests'],
            'patch' => $labels['org.patchrocket.patch-sha256'] ?? null,
            'candidate' => $labels['org.patchrocket.candidate-sha256'] ?? null,
            'base' => $labels['org.patchrocket.base'] ?? null,
            'lock_path' => $labels['org.patchrocket.lock-path'] ?? null,
        ];
    }

    public function dockerImage(string $reference, ?string $display = null, ?string $context = null): string
    {
        $image = $this->inspectImage($reference, $context);

        $existing = $this->inventory->get(hash('sha256', 'image/'.$image['digest']));
        $name = $display ?? ($reference === $image['digest'] ? ($existing['name'] ?? $reference) : $reference);

        return $this->inventory->asset('image', $image['digest'], $name, $image + ['reference' => $name]);
    }

    public function refreshClusters(): array
    {
        $results = [];
        foreach ($this->store->rows("SELECT * FROM assets WHERE kind = 'namespace' ORDER BY name, id") as $namespace) {
            $data = $namespace['data'];
            if (!isset($data['context'], $data['namespace'])) {
                continue;
            }
            $scope = $data['context'].'/'.$data['namespace'];
            if (!empty($data['managed'])) {
                $results[$scope] = ['error' => 'Refresh this scope using its managed connection.'];
                continue;
            }
            try {
                $results[$scope] = ['workloads' => $this->kubernetes($data['context'], $data['namespace'], $data['repository'] ?? null)];
            } catch (\Exception) {
                $results[$scope] = ['error' => 'Discovery failed'];
            }
        }

        return $results;
    }

    public function kubernetes(string $context, string $namespace, ?string $repository, ?string $config = null): int
    {
        $this->validateRepository($repository);
        $base = [...$this->kubeCommand($config), '--context='.$context, '--request-timeout=20s', '--namespace='.$namespace];
        $sets = $this->k8s($base, 'deployment,statefulset,daemonset');
        $pods = $this->k8s($base, 'pods');
        $replicas = $this->k8s($base, 'replicasets');
        return $this->recordKubernetes($context, $namespace, $repository, $sets, $pods, $replicas, null !== $config);
    }

    public function deliveryResources(string $context, string $namespace, bool $allNamespaces, ?string $config): array
    {
        $base = [...$this->kubeCommand($config), '--context='.$context, '--request-timeout=10s'];
        if (!$allNamespaces) {
            $base[] = '--namespace='.$namespace;
        }
        $result = [];
        foreach (['services', 'ingresses.networking.k8s.io', 'deployments', 'applications.argoproj.io'] as $resource) {
            try {
                $result[$resource] = $this->k8s($base, $resource, $allNamespaces);
            } catch (\Exception) {
                $result[$resource] = null;
            }
        }

        return $result;
    }

    public function kubernetesAll(string $context, ?string $config = null): array
    {
        $base = [...$this->kubeCommand($config), '--context='.$context, '--request-timeout=45s'];
        $scopes = array_column(array_column($this->k8s($base, 'namespaces'), 'metadata'), 'name');
        $grouped = [];
        foreach (['deployment,statefulset,daemonset', 'pods', 'replicasets'] as $index => $type) {
            foreach ($this->k8s($base, $type, true) as $record) {
                $grouped[$record['metadata']['namespace']][$index][] = $record;
            }
        }
        $results = [];
        foreach ($scopes as $namespace) {
            $asset = $this->inventory->get(hash('sha256', "namespace/$context/$namespace"));
            // A collection may contain Pods or ReplicaSets without a supported controller.
            $records = $grouped[$namespace] ?? [];
            $results[$namespace] = $this->recordKubernetes($context, $namespace, $asset['data']['repository'] ?? null,
                $records[0] ?? [], $records[1] ?? [], $records[2] ?? [], null !== $config);
        }

        return $results;
    }

    public function argoApplications(string $context, string $namespace, ?string $config): array
    {
        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
            throw new \DomainException('An Argo CD namespace is required.');
        }
        try {
            $json = $this->run([...$this->kubeCommand($config), '--context='.$context, '--request-timeout=20s', '--namespace='.$namespace,
                'get', 'applications.argoproj.io', '-o', 'json']);
            $items = json_decode($json, true, flags: JSON_THROW_ON_ERROR)['items'] ?? null;
            if (is_array($items) && array_is_list($items)) {
                return $items;
            }
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface | \JsonException) {
            // Keep Kubernetes CLI output out of the dashboard.
        }

        throw new \DomainException('Could not list Argo CD Applications. Check the namespace and grant list access to applications.argoproj.io in it.');
    }

    private function recordKubernetes(string $context, string $namespace, ?string $repository, array $sets, array $pods, array $replicas, bool $managed): int
    {
        $cluster = $this->inventory->asset('cluster', $context, $context);
        $ns = $this->inventory->asset('namespace', "$context/$namespace", $namespace, [
            'context' => $context, 'namespace' => $namespace, 'repository' => $repository, 'managed' => $managed,
        ]);
        $this->inventory->link($cluster, 'HOSTS', $ns, 'Kubernetes');
        $workloads = [];
        $owners = [];
        foreach ($replicas as $replica) {
            $owners[$replica['metadata']['uid']] = $this->owner($replica);
        }
        foreach ($sets as $item) {
            $uid = $item['metadata']['uid'];
            $name = $item['metadata']['name'];
            $images = array_column($item['spec']['template']['spec']['containers'] ?? [], 'image');
            $workloads[$uid] = $this->inventory->asset('workload', "$context/$uid", $name, [
                'controller' => $item['kind'], 'declared_images' => $images, 'scope' => "$context/$namespace",
            ]);
            $this->inventory->link($ns, 'HOSTS', $workloads[$uid], 'Kubernetes');
        }
        $observed = [];
        foreach ($pods as $item) {
            $uid = $item['metadata']['uid'];
            $owner = $this->owner($item);
            $owner = $owners[$owner] ?? $owner;
            $pod = $this->inventory->asset('pod', "$context/$uid", $item['metadata']['name'], [
                'phase' => $item['status']['phase'] ?? 'Unknown',
            ]);
            $this->inventory->link($workloads[$owner] ?? $ns, 'HOSTS', $pod, 'Kubernetes');
            foreach ($item['status']['containerStatuses'] ?? [] as $status) {
                $imageId = $status['imageID'] ?? '';
                if ('' === $imageId) {
                    continue;
                }
                $digest = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $imageId);
                $image = $this->inventory->asset('image', $digest, $status['image'], [
                    'digest' => $digest, 'reference' => $status['image'],
                ]);
                $container = $this->inventory->asset('container', "$context/$uid/".$status['name'], $status['name'], [
                    'running' => isset($status['state']['running']), 'image' => $digest,
                    'reference' => $status['image'], 'scope' => "$context/$namespace", 'discovery_state' => 'observed',
                ]);
                $observed[$container] = true;
                $this->inventory->link($pod, 'HOSTS', $container, 'Kubernetes');
                $this->store->db->delete('asset_links', ['source_id' => $container, 'kind' => 'RUNS']);
                $this->inventory->link($container, 'RUNS', $image, 'Kubernetes');
                if ($repository) {
                    $this->inventory->link($image, 'BUILT_FROM', $repository, 'Operator association');
                }
            }
        }

        foreach ($this->store->rows("SELECT id, data FROM assets WHERE kind = 'container'") as $asset) {
            if (($asset['data']['scope'] ?? null) === "$context/$namespace" && !isset($observed[$asset['id']])) {
                $data = array_replace($asset['data'], ['running' => false, 'discovery_state' => 'absent']);
                $this->store->db->update('assets', ['data' => Store::json($data)], ['id' => $asset['id']]);
            }
        }

        return count($workloads);
    }

    private function k8s(array $base, string $resources, bool $allNamespaces = false): array
    {
        $json = $this->run([...$base, 'get', $resources, '-o', 'json', ...($allNamespaces ? ['--all-namespaces'] : [])]);

        return json_decode($json, true, flags: JSON_THROW_ON_ERROR)['items'] ?? [];
    }

    private function owner(array $item): ?string
    {
        foreach ($item['metadata']['ownerReferences'] ?? [] as $owner) {
            if ($owner['controller'] ?? false) {
                return $owner['uid'];
            }
        }

        return null;
    }

    private function validateRepository(?string $id): void
    {
        if ($id && 'repository' !== ($this->inventory->get($id)['kind'] ?? null)) {
            throw new \InvalidArgumentException('Supply a registered repository ID.');
        }
    }

    private function kubeCommand(?string $config): array
    {
        return null === $config ? ['kubectl'] : ['kubectl', '--kubeconfig='.$config, '--cache-dir='.dirname($config).'/cache'];
    }

    private function dockerCommand(?string $context): array
    {
        if (null === $context) {
            return ['docker'];
        }
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/D', $context)) {
            throw new \DomainException('Enter an existing Docker context name.');
        }

        return ['docker', '--context='.$context];
    }

    private function run(array $args): string
    {
        return (new Process($args, timeout: 45))->mustRun()->getOutput();
    }
}
