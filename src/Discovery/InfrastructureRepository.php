<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Asset\Inventory;
use App\Audit\Store;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class InfrastructureRepository
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Repository $repository,
        private readonly DeploymentProvenance $provenance,
    ) {
    }

    public function scan(array $asset): int
    {
        $settings = $asset['data'];
        $revision = $this->repository->revision($settings['path']);
        $subdirectory = $settings['subdirectory'] ?? null;
        $report = $this->inspect(
            $this->repository->configurationFiles($settings['path'], $revision, $subdirectory),
            $settings['canonical_url'] ?? $settings['source_url'] ?? $this->repository->origin($settings['path']),
            $subdirectory,
        );
        $context = $settings['infra_context'] ?? '';
        $matches = [];
        if ($context) {
            foreach ($this->store->iterate("SELECT id, name, data FROM assets WHERE kind = 'workload'") as $workload) {
                $key = implode('/', [$workload['data']['scope'] ?? '', $workload['data']['controller'] ?? '', $workload['name']]);
                $matches[$key][] = $workload['id'];
            }
        }
        foreach ($report['resources'] as &$resource) {
            $key = implode('/', [$context, $resource['namespace'], $resource['kind'], $resource['name']]);
            $observed = $resource['namespace'] && isset($matches[$key]) && 1 === count($matches[$key]) ? $matches[$key][0] : null;
            $resource['observed'] = $observed;
        }
        unset($resource);

        $this->store->db->transactional(function () use ($asset, $revision, $report): void {
            $latest = $this->inventory->get($asset['id']) ?? $asset;
            $this->store->db->delete('asset_links', ['target_id' => $asset['id'], 'kind' => 'DEPLOYED_FROM', 'discovery' => 'GitOps declaration']);
            foreach ($report['resources'] as $resource) {
                if ($resource['observed']
                    && !$this->store->row("SELECT source_id FROM asset_links WHERE source_id = ? AND target_id = ? AND kind = 'DEPLOYED_FROM'", [$resource['observed'], $asset['id']])) {
                    $this->inventory->link($resource['observed'], 'DEPLOYED_FROM', $asset['id'], 'GitOps declaration');
                }
            }
            $data = array_replace($latest['data'], ['revision' => $revision, 'infra_report' => $report, 'scan_source' => 'Static infrastructure scan', 'scanned_at' => gmdate(DATE_ATOM)]);
            $this->store->db->update('assets', ['data' => Store::json($data)], ['id' => $asset['id']]);
        });
        $this->provenance->declare($asset['id'], $context, $revision, $report['applications']);

        return count($report['resources']) + count($report['external']);
    }

    public function inspect(iterable $files, ?string $origin = null, ?string $subdirectory = null): array
    {
        $report = ['resources' => [], 'external' => [], 'terraform' => [], 'applications' => [], 'skipped' => 0];
        $argo = $kustomize = [];
        $repository = Repository::identity($origin);
        foreach ($files as $path => $raw) {
            if (null === $raw) {
                ++$report['skipped'];
                continue;
            }
            if (preg_match('/\.tf(?:\.json)?$/iD', $path)) {
                $report['terraform'][] = $path;
                if (str_ends_with($path, '.tf.json')) {
                    $config = json_decode($raw, true);
                    foreach ((array) ($config['data'] ?? []) as $type => $blocks) {
                        foreach (array_keys((array) $blocks) as $name) {
                            $this->external($report, 'Terraform data source', $type.'.'.$name, $path);
                        }
                    }
                    foreach ((array) ($config['resource'] ?? []) as $type => $blocks) {
                        foreach (array_keys((array) $blocks) as $label) {
                            $name = (string) $label;
                            $kind = 'Terraform '.$type;
                            $namespace = '';
                            $report['resources'][] = compact('kind', 'name', 'namespace', 'path');
                        }
                    }
                }
                continue;
            }
            if (str_contains($raw, '{{')) {
                ++$report['skipped'];
                continue;
            }
            foreach (preg_split('/^---\h*(?:#[^\r\n]*)?\r?$/m', $raw) as $document) {
                try {
                    $data = Yaml::parse($document, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
                    if (is_array($data)) {
                        $this->document($data, $path, $report);
                        $this->namespaceBindings($data, $path, $repository, $argo, $kustomize);
                    }
                } catch (ParseException) {
                    ++$report['skipped'];
                }
            }
        }
        foreach ($report['resources'] as &$resource) {
            if ($resource['namespace'] || !in_array($resource['kind'], ['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job'], true)) {
                continue;
            }
            $path = $resource['path'];
            $parent = dirname($path);
            $directory = trim(($subdirectory ?? '').'/'.('.' === $parent ? '' : $parent), '/');
            $namespaces = $kustomize[$path] ?? $argo[$directory] ?? [];
            if (1 === count($namespaces)) {
                $resource['namespace'] = (string) array_key_first($namespaces);
                $resource['namespace_from'] = isset($kustomize[$path]) ? 'Kustomize' : 'Argo CD';
            }
        }
        unset($resource);

        return $report;
    }

    private function namespaceBindings(array $data, string $path, ?string $repository, array &$argo, array &$kustomize): void
    {
        $kind = $data['kind'] ?? '';
        $api = $this->text($data['apiVersion'] ?? '');
        if ('Kustomization' === $kind && str_starts_with($api, 'kustomize.config.k8s.io/')
            && empty($data['namePrefix']) && empty($data['nameSuffix'])) {
            $namespace = $this->text($data['namespace'] ?? '');
            $directory = '.' === dirname($path) ? '' : dirname($path).'/';
            foreach ((array) ($data['resources'] ?? []) as $resource) {
                if ($namespace && is_string($resource) && preg_match('#^(?:\./)?([a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.(?:ya?ml|json))$#D', $resource, $parts)) {
                    $kustomize[$directory.$parts[1]][$namespace] = true;
                }
            }
        }
        if ('Application' !== $kind || !str_starts_with($api, 'argoproj.io/') || null === $repository) {
            return;
        }
        $spec = $data['spec'] ?? [];
        $destination = $spec['destination'] ?? [];
        $namespace = $this->text($destination['namespace'] ?? '');
        if (!$namespace || ('https://kubernetes.default.svc' !== ($destination['server'] ?? null) && 'in-cluster' !== ($destination['name'] ?? null))) {
            return;
        }
        foreach ((array) ($spec['sources'] ?? [$spec['source'] ?? []]) as $source) {
            if (!is_array($source) || array_intersect(['chart', 'plugin', 'kustomize', 'helm'], array_keys($source))) {
                continue;
            }
            $directory = $this->text($source['path'] ?? '');
            if ('' !== $directory && $repository === Repository::identity($source['repoURL'] ?? null)
                && ('.' === $directory || preg_match('#^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)*/?$#D', $directory))) {
                $argo['.' === $directory ? '' : rtrim($directory, '/')][$namespace] = true;
            }
        }
    }

    private function document(array $data, string $path, array &$report): void
    {
        $kind = $this->text($data['kind'] ?? '');
        $name = $this->text($data['metadata']['name'] ?? '');
        $namespace = $this->text($data['metadata']['namespace'] ?? '');
        if ('List' === $kind) {
            foreach ((array) ($data['items'] ?? []) as $item) {
                if (is_array($item)) {
                    $this->document($item, $path, $report);
                }
            }
            return;
        }
        if ($kind && $name && isset($data['apiVersion'])) {
            $report['resources'][] = compact('kind', 'name', 'namespace', 'path');
        }
        $spec = is_array($data['spec'] ?? null) ? $data['spec'] : [];
        if ('Service' === $kind && 'ExternalName' === ($spec['type'] ?? null)) {
            $this->external($report, 'External service', $spec['externalName'] ?? '', $path);
        }
        if (in_array($kind, ['ExternalSecret', 'ClusterExternalSecret'], true)) {
            $this->external($report, 'External secret store', $spec['secretStoreRef']['name'] ?? '', $path);
        }
        if ('Application' === $kind) {
            if (str_starts_with($this->text($data['apiVersion'] ?? ''), 'argoproj.io/') && ($application = ArgoApplication::read($data, $path))) {
                $report['applications'][] = $application;
            }
            $this->external($report, 'Argo CD destination', $spec['destination']['server'] ?? '', $path);
            foreach ((array) ($spec['sources'] ?? [$spec['source'] ?? []]) as $source) {
                $this->external($report, 'Argo CD source', $source['repoURL'] ?? '', $path);
            }
        }
        if ('Kustomization' === $kind) {
            foreach ([...(array) ($data['resources'] ?? []), ...(array) ($data['bases'] ?? [])] as $resource) {
                if (is_string($resource) && (str_contains($resource, '://') || preg_match('#^(?:github\.com|gitlab\.com|bitbucket\.org)/#', $resource))) {
                    $this->external($report, 'Remote Kustomize source', $resource, $path);
                }
            }
        }
        if ('Chart.yaml' === basename($path)) {
            foreach ((array) ($data['dependencies'] ?? []) as $dependency) {
                $this->external($report, 'Helm chart repository', $dependency['repository'] ?? '', $path);
            }
        }
    }

    private function external(array &$report, string $kind, mixed $value, string $path): void
    {
        $target = $this->text($value);
        if ('' === $target) {
            return;
        }
        $target = preg_replace('#(://)[^/@]+@#', '$1', preg_split('/[?#]/', $target, 2)[0]);
        $report['external'][] = compact('kind', 'target', 'path');
    }

    private function text(mixed $value): string
    {
        return is_string($value) ? substr($value, 0, 300) : '';
    }
}
