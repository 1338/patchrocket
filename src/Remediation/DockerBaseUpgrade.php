<?php
declare(strict_types=1);

namespace App\Remediation;

final class DockerBaseUpgrade implements Strategy
{
    public function plan(array $finding, array $options): array
    {
        $current = $options['current'] ?? '';
        $fixed = $options['fixed'] ?? '';
        $file = $options['dockerfile'] ?? 'Dockerfile';
        if (!preg_match('~^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*Dockerfile(?:\.[a-zA-Z0-9_.-]+)?$~D', $file)) {
            throw new \DomainException('Choose the traced Dockerfile path.');
        }
        if (!empty($options['nginx_overlay'])) {
            return $this->overlayPlan($finding, $options, $file, $fixed);
        }
        if (!preg_match('#^[\w][\w./:@-]+$#D', $current)
            || !preg_match('#^[a-z0-9][a-z0-9.\/:_-]+@sha256:[0-9a-f]{64}$#D', $fixed)
            || $current === $fixed) {
            throw new \DomainException('Supply a current base reference and a different digest-pinned replacement.');
        }

        return ['current' => $current, 'fixed' => $fixed, 'files' => [$file], 'checks' => [
            'Dockerfile reference', 'Rebuilt image scan after approval',
        ]];
    }

    private function overlayPlan(array $finding, array $options, string $file, string $fixed): array
    {
        $module = dirname($file);
        if (!self::supportsOverlay($finding)
            || !preg_match('~^docker\.io/nginx/nginx-unprivileged:[0-9]+\.[0-9]+\.[0-9]+-alpine@sha256:[0-9a-f]{64}$~D', $fixed)
            || !preg_match('~^[a-z0-9][a-z0-9._-]*$~D', $module)
            || !in_array($options['platform'] ?? null, ['linux/amd64', 'linux/arm64'], true)
            || empty($options['advisories'])) {
            throw new \DomainException('The nginx overlay strategy needs a traced module, pinned unprivileged Alpine base, platform, and a fixed package version.');
        }

        return [
            'current' => '${BASE_REGISTRY}/nginxinc/nginx-unprivileged:1.30-alpine',
            'fixed' => '${BASE_REGISTRY}/'.substr($fixed, strlen('docker.io/')), 'base_image' => $fixed,
            'files' => [$file], 'nginx_overlay' => true, 'module' => $module,
            'platform' => $options['platform'], 'package_fixed' => $finding['fixed'], 'advisories' => $options['advisories'],
            'checks' => ['Dockerfile reference', 'Local container build', 'nginx configuration and package', 'Rebuilt image scan'],
        ];
    }

    public function apply(string $workspace, array $plan, bool $demo, callable $evidence): array
    {
        $file = $workspace.'/'.$plan['files'][0];
        $updated = $this->updatedDockerfile(file_get_contents($file), $plan);
        file_put_contents($file, $updated);
        $evidence('Dockerfile reference', ['passed' => true, 'log' => $plan['fixed']]);

        return $plan['files'];
    }

    public static function supportsOverlay(array $finding): bool
    {
        return 'nginx' === ($finding['package'] ?? null) && 'alpine' === ($finding['type'] ?? null)
            && (bool) preg_match('~^[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+$~D', $finding['fixed'] ?? '');
    }

    public function updatedDockerfile(string $original, array $plan): string
    {
        if (!empty($plan['nginx_overlay'])) {
            $original = $this->removeOverlay($original);
        }
        $pattern = '/^(\h*FROM\h+(?:--platform=\S+\h+)?)'.preg_quote($plan['current'], '/').'(?=\h|\r?$)/mi';
        $updated = preg_replace_callback($pattern, static fn (array $m): string => $m[1].$plan['fixed'], $original, -1, $count);
        if (1 !== $count) {
            throw new \DomainException('The current base must occur in exactly one static FROM instruction.');
        }
        return $updated;
    }

    private function removeOverlay(string $original): string
    {
        if (!preg_match('/^ARG BASE_REGISTRY=docker\.io\r?$/m', $original)) {
            throw new \DomainException('The traced Dockerfile must retain the Docker Hub registry argument used by Jenkins.');
        }
        $stage = <<<'REGEX'
~^(?:# nginx [^\r\n]+\r?\n# binary from the official image[^\r\n]*\r?\n)?FROM \$\{BASE_REGISTRY\}/library/nginx:[0-9.]+-alpine AS nginx-patched\r?\n~m
REGEX;
        $contents = preg_replace($stage, '', $original, -1, $stages);
        $copy = <<<'REGEX'
~^COPY --from=nginx-patched (/usr/sbin/nginx /usr/sbin/nginx|/usr/lib/nginx/modules/ /usr/lib/nginx/modules/)\r?\n~m
REGEX;
        preg_match_all($copy, $original, $copies);
        $contents = preg_replace($copy, '', $contents);
        if (1 !== $stages || 2 !== count(array_unique($copies[1])) || str_contains($contents, 'nginx-patched')) {
            throw new \DomainException('The Dockerfile does not match the expected nginx binary and modules overlay.');
        }

        return $contents;
    }
}
