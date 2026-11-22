<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Discovery\ArgoApplication;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class IacImageUpgrade
{
    private const YAML_FLAGS = Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE;

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
            "SELECT r.id, r.name, r.data, w.id AS workload, w.name AS deployment, c.name AS container,
                c.data AS runtime, app.data AS application
            FROM asset_links runs JOIN assets c ON c.id = runs.source_id AND c.kind = 'container'
            JOIN asset_links contains_container ON contains_container.target_id = c.id AND contains_container.kind = 'HOSTS'
            JOIN assets p ON p.id = contains_container.source_id AND p.kind = 'pod'
            JOIN asset_links contains_pod ON contains_pod.target_id = p.id AND contains_pod.kind = 'HOSTS'
            JOIN assets w ON w.id = contains_pod.source_id AND w.kind = 'workload'
            LEFT JOIN asset_links managed ON managed.source_id = w.id AND managed.kind = 'MANAGED_BY'
            LEFT JOIN assets app ON app.id = managed.target_id AND app.kind = 'argo-application'
            JOIN asset_links declared ON declared.kind = 'DEPLOYED_FROM'
                AND (declared.source_id = w.id OR declared.source_id = app.id)
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
            $url = ($repo['canonical_url'] ?? '') ?: ($repo['source_url'] ?? '');
            $asset = ['id' => $row['id'], 'name' => $row['name'], 'data' => $repo];
            $deployment = $row['deployment'];
            $container = $row['container'];
            $current = $runtime['reference'];
            if ($row['application'] && str_starts_with($runtime['scope'] ?? '', $context.'/')) {
                $application = json_decode($row['application'], true, flags: JSON_THROW_ON_ERROR);
                $namespace = substr($runtime['scope'], strlen($context) + 1);
                if ($argo = $this->argoSource($application, $asset['id'], $url, $context, $namespace, $deployment, $current)) {
                    $source = $argo + compact('context', 'namespace', 'deployment', 'container', 'current');
                    $targets[Store::json([$asset['id'], $source])] = compact('source', 'asset', 'url');
                }
            }
            foreach ($repo['infra_report']['resources'] ?? [] as $resource) {
                $namespace = $resource['namespace'] ?? '';
                if (($resource['observed'] ?? null) !== $row['workload'] || 'Deployment' !== $resource['kind']
                    || $row['deployment'] !== $resource['name'] || !$namespace || isset($resource['namespace_from'])
                    || $context.'/'.$namespace !== ($runtime['scope'] ?? null)) {
                    continue;
                }
                $source = ['file' => $resource['path']] + compact('context', 'namespace', 'deployment', 'container', 'current');
                $targets[Store::json([$asset['id'], $source])] = compact('source', 'asset', 'url');
            }
        }

        return 1 === count($targets) ? reset($targets) : null;
    }

    private function argoSource(array $application, string $repository, string $url, string $context, string $namespace, string $deployment, string $current): ?array
    {
        $declaration = $application['declarations'][$repository] ?? [];
        $observed = $application['observation'] ?? [];
        $workload = ['kind' => 'Deployment', 'name' => $deployment, 'namespace' => $namespace];
        if (empty($declaration['file']) || ($application['context'] ?? null) !== $context
            || empty($observed['in_cluster']) || empty($declaration['in_cluster'])
            || ($observed['destination'] ?? null) !== $namespace || ($declaration['destination'] ?? null) !== $namespace
            || !in_array($workload, $observed['resources'] ?? [], true)
            || !preg_match('~:([a-zA-Z0-9_.-]+(?:@sha256:[a-f0-9]{64})?)$~D', $current, $tag)) {
            return null;
        }

        $sources = self::argoSources($observed);
        $identity = Repository::identity($url);
        $helm = array_filter($sources, static fn (array $source): bool =>
            $identity && Repository::identity($source['repository']) === $identity && '' !== $source['path']
            && '' === $source['chart'] && $deployment === $source['release'] && $tag[1] === $source['image_tag']);
        if (1 !== count($helm)) {
            return null;
        }

        return [
            'file' => $declaration['file'],
            'argo' => [
                'name' => $observed['name'], 'namespace' => $observed['namespace'], 'sources' => $sources,
                'helm_source' => array_key_first($helm),
            ],
        ];
    }

    private static function argoSources(array $application): array
    {
        return array_map(static function (array $source): array {
            unset($source['synced_revision']);

            return $source;
        }, $application['sources'] ?? []);
    }

    public function plan(array $target, array $image, string $fixed): array
    {
        $digest = $image['data']['digest'] ?? '';
        $platform = $image['data']['platform'] ?? '';
        if (!preg_match('~^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9_.-]+)?@sha256:[a-f0-9]{64}$~D', $fixed)
            || self::repository($fixed) !== self::repository($digest) || explode('@', $fixed)[1] === (explode('@', $digest)[1] ?? '')) {
            throw new RemediationFieldError('fixed', 'Enter a different digest-pinned image from the same upstream repository.');
        }
        if (!preg_match('~^linux/[a-z0-9]+(?:/v[0-9]+)?$~D', $platform)) {
            throw new \DomainException('The observed image needs a recorded Linux platform before PatchRocket can scan its replacement.');
        }
        if (isset($target['argo']) && !preg_match('~:[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}$~D', $fixed)) {
            throw new RemediationFieldError('fixed', 'Enter the replacement image with both a tag and its SHA-256 digest for the Helm image.tag parameter.');
        }

        return $target + ['fixed' => $fixed, 'platform' => $platform, 'files' => [$target['file']]];
    }

    /** @return array{string, string} */
    public function editCommitted(Repository $repository, string $path, string $revision, string $branch, array $plan): array
    {
        if (isset($plan['argo'])) {
            $helm = $plan['argo']['sources'][$plan['argo']['helm_source']];
            if ($helm['revision'] !== $branch) {
                throw new RemediationFieldError('base', 'Choose the branch tracked by the Argo CD Helm source.');
            }
            $template = $repository->committedFile($path, $revision, $helm['path'].'/templates/deployment.yaml');
            if (1 !== preg_match_all('~^\h*image:\h*"{{\h*(?:required\h+"[^"\r\n]+"\h+)?\.Values\.image\.repository\h*}}:{{\h*\.Values\.image\.tag\h*}}"\h*\r?$~m', $template)) {
                throw new \DomainException('The committed Helm Deployment template must use image.repository and image.tag directly in its container image.');
            }
        }

        $raw = $repository->committedFile($path, $revision, $plan['file']);

        return [$raw, $this->edit($raw, $plan)];
    }

    public function edit(string $raw, array $plan): string
    {
        $segments = preg_split('/^(---\h*(?:#[^\r\n]*)?\r?\n)/m', $raw, -1, PREG_SPLIT_DELIM_CAPTURE);
        $workloads = [];
        foreach ($segments as $index => $segment) {
            if (0 !== $index % 2) {
                continue;
            }
            $doc = Yaml::parse($segment, self::YAML_FLAGS);
            if (isset($plan['argo'])) {
                if ('Application' === ($doc['kind'] ?? null) && 'argoproj.io/v1alpha1' === ($doc['apiVersion'] ?? null)
                    && $plan['argo']['name'] === ($doc['metadata']['name'] ?? null)
                    && $plan['argo']['namespace'] === ($doc['metadata']['namespace'] ?? null)) {
                    $workloads[$index] = $doc;
                }
                continue;
            }
            if ('apps/v1' === ($doc['apiVersion'] ?? null) && 'Deployment' === ($doc['kind'] ?? null)
                && $plan['deployment'] === ($doc['metadata']['name'] ?? null) && $plan['namespace'] === ($doc['metadata']['namespace'] ?? null)) {
                $workloads[$index] = $doc;
            }
        }
        if (1 !== count($workloads)) {
            $kind = isset($plan['argo']) ? 'Argo CD Application' : 'Deployment';
            throw new \DomainException('Expected one committed '.$kind.' with the traced name and namespace.');
        }
        $index = array_key_first($workloads);
        $doc = $workloads[$index];
        if (isset($plan['argo'])) {
            $segments[$index] = $this->editArgo($segments[$index], $doc, $plan);

            return implode('', $segments);
        }
        $containers = $doc['spec']['template']['spec']['containers'] ?? [];
        $matches = array_filter($containers, static fn (array $c): bool => ($c['name'] ?? null) === $plan['container']);
        $position = array_key_first($matches);
        $image = $matches[$position]['image'] ?? null;
        if (1 !== count($matches) || !is_string($image) || self::canonical($image) !== self::canonical($plan['current'])) {
            throw new \DomainException('The committed container image differs from the traced deployment. Refresh inventory before preparing a patch.');
        }

        $doc['spec']['template']['spec']['containers'][$position]['image'] = $plan['fixed'];
        $segments[$index] = self::editScalar($segments[$index], $doc, 'image', $image, $plan['fixed']);

        return implode('', $segments);
    }

    private function editArgo(string $raw, array $doc, array $plan): string
    {
        $actual = ArgoApplication::read($doc, $plan['file']);
        $expected = $plan['argo'];
        if (empty($actual['in_cluster']) || $actual['destination'] !== $plan['namespace']
            || self::argoSources($actual) !== $expected['sources']) {
            throw new \DomainException('The committed Argo CD sources differ from the observed application. Refresh inventory or choose its current infrastructure branch.');
        }

        $position = $expected['helm_source'];
        if (isset($doc['spec']['sources'])) {
            if (!array_is_list($doc['spec']['sources']) || count($doc['spec']['sources']) !== count($expected['sources'])) {
                throw new \DomainException('The committed Argo CD source list contains unsupported entries.');
            }
            $parameters = &$doc['spec']['sources'][$position]['helm']['parameters'];
        } else {
            $parameters = &$doc['spec']['source']['helm']['parameters'];
        }
        $matches = array_keys(array_filter($parameters ?? [], static fn ($parameter): bool =>
            is_array($parameter) && 'image.tag' === ($parameter['name'] ?? null)));
        $tag = $expected['sources'][$position]['image_tag'];
        if (1 !== count($matches) || ($parameters[$matches[0]]['value'] ?? null) !== $tag) {
            throw new \DomainException('The traced Helm source needs one explicit image.tag parameter matching the running image.');
        }
        $replacement = substr($plan['fixed'], strrpos(explode('@', $plan['fixed'], 2)[0], ':') + 1);
        $parameters[$matches[0]]['value'] = $replacement;

        return self::editScalar($raw, $doc, 'value', $tag, $replacement);
    }

    private static function editScalar(string $segment, array $doc, string $key, string $current, string $fixed): string
    {
        $pattern = '~^\h*(?:-\h+)?'.$key.':\h*(["\']?)('.preg_quote($current, '~').')\1\h*(?:#[^\r\n]*)?\r?$~m';
        preg_match_all($pattern, $segment, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        foreach ($matches as $match) {
            [$old, $offset] = $match[2];
            $candidate = substr_replace($segment, $fixed, $offset, strlen($old));
            if (Yaml::parse($candidate, self::YAML_FLAGS) === $doc) {
                return $candidate;
            }
        }

        throw new \DomainException('The traced image reference must be a static YAML scalar.');
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
