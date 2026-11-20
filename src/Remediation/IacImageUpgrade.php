<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Intelligence\Scanner;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class IacImageUpgrade
{
    public function __construct(
        private readonly Store $store,
        private readonly Scanner $scanner,
        private readonly HarborRelease $registry,
    ) {
    }

    public function target(array $image): ?array
    {
        if ('image' !== $image['kind']) {
            return null;
        }
        $targets = [];
        foreach ($this->store->rows(
            "SELECT r.id, r.name, r.data, w.id AS workload, w.name AS deployment, c.name AS container, c.data AS runtime
            FROM asset_links runs JOIN assets c ON c.id = runs.source_id AND c.kind = 'container'
            JOIN asset_links contains_container ON contains_container.target_id = c.id AND contains_container.kind = 'HOSTS'
            JOIN assets p ON p.id = contains_container.source_id AND p.kind = 'pod'
            JOIN asset_links contains_pod ON contains_pod.target_id = p.id AND contains_pod.kind = 'HOSTS'
            JOIN assets w ON w.id = contains_pod.source_id AND w.kind = 'workload'
            JOIN asset_links declared ON declared.source_id = w.id AND declared.kind = 'DEPLOYED_FROM'
            JOIN assets r ON r.id = declared.target_id AND r.kind = 'repository'
            WHERE runs.target_id = ? AND runs.kind = 'RUNS'", [$image['id']],
        ) as $row) {
            $repo = $row['data'];
            $runtime = json_decode($row['runtime'], true, flags: JSON_THROW_ON_ERROR);
            $context = $repo['infra_context'] ?? '';
            if ('infrastructure' !== ($repo['role'] ?? null) || isset($repo['subdirectory'])
                || !$context || empty($runtime['running']) || empty($runtime['reference'])) {
                continue;
            }
            foreach ($repo['infra_report']['resources'] ?? [] as $resource) {
                $namespace = $resource['namespace'] ?? '';
                if (($resource['observed'] ?? null) !== $row['workload'] || 'Deployment' !== $resource['kind']
                    || $row['deployment'] !== $resource['name'] || !$namespace || isset($resource['namespace_from'])
                    || $context.'/'.$namespace !== ($runtime['scope'] ?? null)) {
                    continue;
                }
                $target = [
                    'file' => $resource['path'], 'context' => $context, 'namespace' => $namespace,
                    'deployment' => $row['deployment'], 'container' => $row['container'], 'current' => $runtime['reference'],
                ];
                $targets[Store::json([$row['id'], $target])] = [
                    'source' => $target, 'asset' => ['id' => $row['id'], 'name' => $row['name'], 'data' => $repo],
                    'url' => ($repo['canonical_url'] ?? '') ?: ($repo['source_url'] ?? ''),
                ];
            }
        }

        return 1 === count($targets) ? reset($targets) : null;
    }

    public function plan(array $target, array $image, string $fixed): array
    {
        $digest = $image['data']['digest'] ?? '';
        $platform = $image['data']['platform'] ?? '';
        if (!preg_match('~^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9_.-]+)?@sha256:[a-f0-9]{64}$~D', $fixed)
            || self::repository($fixed) !== self::repository($digest) || explode('@', $fixed)[1] === (explode('@', $digest)[1] ?? '')
            || !preg_match('~^linux/[a-z0-9]+(?:/v[0-9]+)?$~D', $platform)) {
            throw new \DomainException('Enter a different digest-pinned image from the same upstream repository.');
        }

        return $target + ['fixed' => $fixed, 'platform' => $platform, 'files' => [$target['file']]];
    }

    public function edit(string $raw, array $plan): string
    {
        $segments = preg_split('/^(---\h*(?:#[^\r\n]*)?\r?\n)/m', $raw, -1, PREG_SPLIT_DELIM_CAPTURE);
        $workloads = [];
        foreach ($segments as $index => $segment) {
            if (0 !== $index % 2) {
                continue;
            }
            $doc = Yaml::parse($segment, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
            if ('apps/v1' === ($doc['apiVersion'] ?? null) && 'Deployment' === ($doc['kind'] ?? null)
                && $plan['deployment'] === ($doc['metadata']['name'] ?? null) && $plan['namespace'] === ($doc['metadata']['namespace'] ?? null)) {
                $workloads[$index] = $doc;
            }
        }
        if (1 !== count($workloads)) {
            throw new \DomainException('Expected one committed Deployment with the traced name and namespace.');
        }
        $index = array_key_first($workloads);
        $doc = $workloads[$index];
        $containers = $doc['spec']['template']['spec']['containers'] ?? [];
        $matches = array_filter($containers, static fn (array $c): bool => ($c['name'] ?? null) === $plan['container']);
        $position = array_key_first($matches);
        $image = $matches[$position]['image'] ?? null;
        if (1 !== count($matches) || !is_string($image) || self::canonical($image) !== self::canonical($plan['current'])) {
            throw new \DomainException('The committed container image differs from the traced deployment. Refresh inventory before preparing a patch.');
        }

        $doc['spec']['template']['spec']['containers'][$position]['image'] = $plan['fixed'];
        $segment = $segments[$index];
        $pattern = '~^\h*(?:-\h+)?image:\h*(["\']?)('.preg_quote($image, '~').')\1\h*(?:#[^\r\n]*)?\r?$~m';
        preg_match_all($pattern, $segment, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($matches as $match) {
            [$old, $offset] = $match[2];
            $candidate = substr_replace($segment, $plan['fixed'], $offset, strlen($old));
            if (Yaml::parse($candidate, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE) === $doc) {
                $segments[$index] = $candidate;

                return implode('', $segments);
            }
        }

        throw new \DomainException('The traced image must be a static YAML image field.');
    }

    public function verify(array $plan, array $finding, string $scratch): array
    {
        $artifact = $this->registry->upstream($plan['fixed'], $plan['platform'], $scratch);
        $local = new Process(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', $artifact['image']], timeout: 10);
        try {
            $digests = 0 === $local->run() ? json_decode($local->getOutput(), true) : null;
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $digests = null;
        }
        $cached = is_array($digests) && in_array($artifact['image'], array_map(self::canonical(...), array_filter($digests, 'is_string')), true);
        $report = $cached
            ? $this->scanner->image($artifact['image'], $scratch)
            : $this->scanner->registryImage($artifact['image'], $plan['platform'], $scratch, true);
        $analyzed = array_filter($report['analyzed'], static fn (array $target): bool =>
            $finding['type'] === ($target['Type'] ?? null) && in_array($target['Class'] ?? '', ['os-pkgs', 'lang-pkgs'], true));
        $remaining = array_filter($report['findings'], static fn (array $row): bool => $finding['advisory'] === $row['advisory']);
        if (!$analyzed || $remaining) {
            throw new \DomainException('Trivy could not confirm that the replacement image clears the selected advisory.');
        }

        return $artifact + ['advisories' => [$finding['advisory']]];
    }

    private static function canonical(string $reference): string
    {
        $host = explode('/', $reference, 2)[0];
        if (!str_contains($reference, '/') || !strpbrk($host, '.:') && 'localhost' !== $host) {
            return 'docker.io/'.(str_contains($reference, '/') ? '' : 'library/').$reference;
        }

        return $reference;
    }

    private static function repository(string $reference): string
    {
        return preg_replace('~:[^/]+$~', '', explode('@', self::canonical($reference), 2)[0]);
    }
}
