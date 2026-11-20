<?php
declare(strict_types=1);

namespace App\Discovery;

final class ArgoApplication
{
    public const WORKLOADS = ['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job'];

    public static function read(array $object, ?string $file = null): ?array
    {
        $metadata = $object['metadata'] ?? [];
        $spec = $object['spec'] ?? [];
        $destination = $spec['destination'] ?? [];
        $name = self::text($metadata['name'] ?? null);
        $namespace = self::text($metadata['namespace'] ?? null);
        if (!$name || !$namespace) {
            return null;
        }
        $server = Repository::safeUrl($destination['server'] ?? null);
        $cluster = self::text($destination['name'] ?? null);
        $status = $object['status'] ?? [];
        $sync = $status['sync'] ?? [];
        $sources = [];
        foreach (array_values((array) ($spec['sources'] ?? [$spec['source'] ?? []])) as $position => $source) {
            if (!is_array($source) || !($repo = Repository::safeUrl($source['repoURL'] ?? null))) {
                continue;
            }
            $helm = $source['helm'] ?? [];
            $tag = self::text($helm['valuesObject']['image']['tag'] ?? null);
            foreach ((array) ($helm['parameters'] ?? []) as $parameter) {
                if ('image.tag' === ($parameter['name'] ?? null)) {
                    $tag = self::text($parameter['value'] ?? null);
                }
            }
            $sources[] = [
                'repository' => $repo, 'path' => self::text($source['path'] ?? null), 'chart' => self::text($source['chart'] ?? null),
                'ref' => self::text($source['ref'] ?? null), 'revision' => self::text($source['targetRevision'] ?? null),
                'synced_revision' => self::text($sync['revisions'][$position] ?? (0 === $position ? ($sync['revision'] ?? null) : null)),
                'release' => self::text($helm['releaseName'] ?? null), 'image_tag' => $tag,
                'values_files' => array_values(array_filter(array_map(self::text(...), (array) ($helm['valueFiles'] ?? [])))),
            ];
        }
        $resources = [];
        if (null === $file) {
            foreach ((array) ($status['resources'] ?? []) as $resource) {
                $kind = $resource['kind'] ?? null;
                $resourceName = self::text($resource['name'] ?? null);
                $resourceNamespace = self::text($resource['namespace'] ?? null);
                if (in_array($kind, self::WORKLOADS, true) && $resourceName && $resourceNamespace) {
                    $resources[] = ['kind' => $kind, 'name' => $resourceName, 'namespace' => $resourceNamespace];
                }
            }
        }

        return [
            'name' => $name, 'namespace' => $namespace, 'file' => $file, 'sources' => $sources, 'resources' => $resources,
            'destination' => self::text($destination['namespace'] ?? null),
            'cluster' => $server ?: $cluster,
            'in_cluster' => 'https://kubernetes.default.svc' === $server || ('' === $server && 'in-cluster' === $cluster),
            'sync' => self::text($sync['status'] ?? null), 'health' => self::text($status['health']['status'] ?? null),
        ];
    }

    private static function text(mixed $value): string
    {
        return is_string($value) && strlen($value) <= 512 && !preg_match('/[\x00-\x1f]/', $value) ? $value : '';
    }
}
