<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Asset\Inventory;
use App\Audit\Store;
use Symfony\Component\Process\Exception\ExceptionInterface;

final class DeploymentProvenance
{
    private const BUILD_EVIDENCE = 'Jenkinsfile and observed image tag';
    private const DECLARATION = 'Argo CD Helm release';
    private const OBSERVATION = 'Argo CD resource inventory';

    public function __construct(private readonly Store $store, private readonly Inventory $inventory, private readonly Repository $repository)
    {
    }

    public function declare(string $repository, string $context, string $revision, array $applications): void
    {
        $contexts = $this->store->db->transactional(function () use ($repository, $context, $revision, $applications): array {
            $seen = $contexts = [];
            if ('' !== $context) {
                $contexts[$context] = true;
                foreach ($applications as $app) {
                    $id = $this->id($context, $app);
                    $data = $this->inventory->get($id)['data']['declarations'] ?? [];
                    $data[$repository] = $app + ['infra_revision' => $revision];
                    $seen[$this->save($context, $app, ['declarations' => $data])] = true;
                }
            }
            foreach ($this->applications() as $entry) {
                $data = $entry['data'];
                if (!isset($seen[$entry['id']]) && isset($data['declarations'][$repository])) {
                    unset($data['declarations'][$repository]);
                    $contexts[$data['context']] = true;
                    $this->save($data['context'], $data, ['declarations' => $data['declarations']]);
                }
            }

            return array_keys($contexts);
        });
        foreach ($contexts as $scope) {
            $this->refresh($scope);
        }
    }

    public function observe(string $context, string $namespace, array $objects): int
    {
        $count = $this->store->db->transactional(function () use ($context, $namespace, $objects): int {
            $seen = [];
            foreach ($objects as $object) {
                if (($object['metadata']['namespace'] ?? null) !== $namespace || !($app = ArgoApplication::read($object))) {
                    continue;
                }
                $seen[$this->save($context, $app, ['observation' => $app + ['observed_at' => gmdate(DATE_ATOM)]])] = true;
            }
            foreach ($this->applications() as $entry) {
                $data = $entry['data'];
                if ($data['context'] === $context && $data['namespace'] === $namespace && isset($data['observation']) && !isset($seen[$entry['id']])) {
                    $this->save($context, $data, ['observation' => null]);
                }
            }

            return count($seen);
        });
        $this->refresh($context);

        return $count;
    }

    public function refresh(string $context): void
    {
        $apps = array_column(array_filter($this->applications(), static fn (array $row): bool => $row['data']['context'] === $context), 'data', 'id');
        if (!$apps) {
            return;
        }
        $workloads = $this->matchWorkloads($context, $apps);
        $buildSources = $this->matchBuilds($apps, $workloads);
        $this->store->db->transactional(function () use ($context, $apps, $workloads, $buildSources): void {
            foreach ($apps as $id => $app) {
                foreach ([self::OBSERVATION, self::DECLARATION] as $evidence) {
                    $this->store->db->delete('asset_links', ['target_id' => $id, 'kind' => 'MANAGED_BY', 'discovery' => $evidence]);
                }
                $this->store->db->delete('asset_links', ['source_id' => $id, 'kind' => 'DEPLOYED_FROM', 'discovery' => 'Argo CD application definition']);
                foreach (array_keys($app['declarations'] ?? []) as $repository) {
                    $this->inventory->link($id, 'DEPLOYED_FROM', $repository, 'Argo CD application definition');
                }
            }
            foreach ($workloads as $workload => [$app, $evidence]) {
                $this->inventory->link($workload, 'MANAGED_BY', $app, $evidence);
            }
            foreach ($this->store->rows("SELECT id, data FROM assets WHERE kind = 'image'") as $image) {
                $data = $image['data'];
                $previous = $data['build_sources'] ?? [];
                $updated = $previous;
                unset($updated[$context]);
                if (isset($buildSources[$image['id']]) && 1 === count($buildSources[$image['id']])) {
                    $updated[$context] = reset($buildSources[$image['id']]);
                }
                if ($updated === $previous) {
                    continue;
                }
                $this->store->db->delete('asset_links', ['source_id' => $image['id'], 'kind' => 'BUILD_SOURCE', 'discovery' => self::BUILD_EVIDENCE]);
                foreach (array_unique(array_column($updated, 'repository')) as $repository) {
                    $this->inventory->link($image['id'], 'BUILD_SOURCE', $repository, self::BUILD_EVIDENCE);
                }
                $data['build_sources'] = $updated;
                $this->store->db->update('assets', ['data' => Store::json($data)], ['id' => $image['id']]);
            }
        });
    }

    private function matchWorkloads(string $context, array $apps): array
    {
        $observed = $declared = [];
        foreach ($apps as $id => $app) {
            if (($app['observation']['in_cluster'] ?? false)) {
                foreach ($app['observation']['resources'] as $resource) {
                    $observed[$resource['namespace'].'/'.$resource['kind'].'/'.$resource['name']][$id] = true;
                }
            }
            if (isset($app['observation']) || 1 !== count($app['declarations'] ?? [])) {
                continue;
            }
            $definition = reset($app['declarations']);
            foreach ($definition['in_cluster'] ? $definition['sources'] : [] as $source) {
                if ($definition['destination'] && $source['release']) {
                    $declared[$definition['destination'].'/'.$source['release']][$id] = true;
                }
            }
        }
        $workloads = [];
        $names = [];
        foreach ($this->store->iterate("SELECT id, name, data FROM assets WHERE kind = 'workload'") as $row) {
            $scope = $row['data']['scope'] ?? '';
            if (!str_starts_with($scope, $context.'/')) {
                continue;
            }
            $namespace = substr($scope, strlen($context) + 1);
            $kind = $row['data']['controller'];
            $key = $namespace.'/'.$kind.'/'.$row['name'];
            $names[$namespace.'/'.$row['name']][] = [$row['id'], $key];
        }
        foreach ($names as $name => $entries) {
            foreach ($entries as [$workload, $key]) {
                if (isset($observed[$key]) && 1 === count($observed[$key]) && 1 === count(array_keys(array_column($entries, 1), $key, true))) {
                    $workloads[$workload] = [array_key_first($observed[$key]), self::OBSERVATION];
                } elseif (!isset($observed[$key]) && 1 === count($entries) && 1 === count($declared[$name] ?? [])) {
                    $workloads[$workload] = [array_key_first($declared[$name]), self::DECLARATION];
                }
            }
        }

        return $workloads;
    }

    private function matchBuilds(array $apps, array $workloads): array
    {
        if (!$workloads) {
            return [];
        }
        $repositories = $candidates = $cache = $result = [];
        foreach ($this->store->iterate("SELECT id, name, data FROM assets WHERE kind = 'repository'") as $row) {
            $data = $row['data'];
            if (isset($data['subdirectory']) || ($data['role'] ?? null) === 'infrastructure' || empty($data['path'])) {
                continue;
            }
            $identity = Repository::identity($data['canonical_url'] ?? $data['source_url'] ?? $this->repository->origin($data['path']));
            if ($identity) {
                $repositories[$identity][] = $row;
            }
        }
        foreach ($apps as $id => $app) {
            $definition = $app['observation'] ?? (1 === count($app['declarations'] ?? []) ? reset($app['declarations']) : null);
            foreach ($definition['sources'] ?? [] as $source) {
                $identity = Repository::identity($source['repository']);
                if (null !== $identity && 1 === count($repositories[$identity] ?? [])) {
                    $row = $repositories[$identity][0];
                    $candidates[$id][$row['id']] = ['path' => $row['data']['path'], 'name' => $row['name']];
                }
            }
        }
        foreach ($this->store->iterate(<<<'SQL'
            SELECT wp.source_id AS workload, ci.target_id AS image, container.data
            FROM asset_links wp
            JOIN assets pod ON pod.id = wp.target_id AND pod.kind = 'pod'
            JOIN asset_links pc ON pc.source_id = pod.id AND pc.kind = 'HOSTS'
            JOIN assets container ON container.id = pc.target_id AND container.kind = 'container'
            JOIN asset_links ci ON ci.source_id = container.id AND ci.kind = 'RUNS'
            WHERE wp.kind = 'HOSTS'
            SQL) as $row) {
            $app = $workloads[$row['workload']][0] ?? null;
            $container = $row['data'];
            if (!isset($candidates[$app]) || 'observed' !== ($container['discovery_state'] ?? '') || empty($container['running'])
                || !preg_match('~^([^@]+):([a-f0-9]{40}|[a-f0-9]{64})$~D', $container['reference'] ?? '', $tag)
                || !preg_match('~^'.preg_quote($tag[1], '~').'@sha256:[a-f0-9]{64}$~D', $container['image'] ?? '')) {
                continue;
            }
            [, $imageName, $revision] = $tag;
            foreach ($candidates[$app] as $repository => $source) {
                $key = $repository.'/'.$revision;
                if (!isset($cache[$key])) {
                    try {
                        $cache[$key] = JenkinsBuilds::inspect($this->repository->buildFiles($source['path'], $revision));
                    } catch (ExceptionInterface | \DomainException) {
                        $cache[$key] = [];
                    }
                }
                foreach ($cache[$key][$imageName] ?? [] as $build) {
                    $index = $key.'/'.$build['jenkinsfile'].'/'.$build['dockerfile'];
                    $result[$row['image']][$index] ??= $build + [
                        'repository' => $repository, 'repository_name' => $source['name'], 'revision' => $revision, 'applications' => [],
                    ];
                    $result[$row['image']][$index]['applications'][$app] = $apps[$app]['name'];
                }
            }
        }

        return $result;
    }

    private function applications(): array
    {
        return $this->store->rows("SELECT id, data FROM assets WHERE kind = 'argo-application'");
    }

    private function key(string $context, array $app): string
    {
        return $context.'/'.$app['namespace'].'/'.$app['name'];
    }

    private function id(string $context, array $app): string
    {
        return hash('sha256', 'argo-application/'.$this->key($context, $app));
    }

    private function save(string $context, array $app, array $data): string
    {
        return $this->inventory->asset('argo-application', $this->key($context, $app), $app['name'], $data + [
            'context' => $context, 'namespace' => $app['namespace'], 'name' => $app['name'],
        ]);
    }
}
