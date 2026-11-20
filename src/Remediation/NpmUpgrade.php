<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Verification\Sandbox;
use Composer\Semver\Semver;

final class NpmUpgrade implements Strategy
{
    public function __construct(private readonly Sandbox $sandbox)
    {
    }

    public function plan(array $finding, array $options): array
    {
        if ('npm' !== $finding['type'] || !preg_match('#^(?:@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*$#D', $finding['package'])) {
            throw new \DomainException('Choose a supported npm package finding.');
        }
        $versions = array_filter(
            preg_split('/\s*,\s*/', trim($finding['fixed'])),
            static fn (string $v): bool => 1 === preg_match('/^\d+\.\d+\.\d+$/D', $v) && Semver::satisfies($finding['version'], '<'.$v),
        );
        $fixed = Semver::sort($versions)[0] ?? null;
        if (!$fixed) {
            throw new \DomainException('No supported fixed npm version is available.');
        }

        return [
            'package' => $finding['package'], 'installed' => $finding['version'], 'fixed' => $fixed,
            'files' => ['package.json', 'package-lock.json'],
            'checks' => ['npm ci', 'npm test', 'Dependency rescan'],
        ];
    }

    public function apply(string $workspace, array $plan, bool $demo, callable $evidence): array
    {
        $manifest = json_decode(file_get_contents($workspace.'/package.json'), true, flags: JSON_THROW_ON_ERROR);
        $package = $plan['package'];
        $section = isset($manifest['dependencies'][$package]) ? 'dependencies' : 'devDependencies';
        if (!isset($manifest[$section][$package]) || isset($manifest['workspaces']) || !isset($manifest['scripts']['test'])) {
            throw new \DomainException('npm upgrades require a direct dependency, a test script, and a single-package project.');
        }
        if ($this->version($workspace, $package) !== $plan['installed']) {
            throw new \DomainException('The package lock no longer matches the finding.');
        }
        // Write the approved exact version, then let npm resolve the lockfile without lifecycle hooks.
        $manifest[$section][$package] = $plan['fixed'];
        file_put_contents($workspace.'/package.json', json_encode($manifest, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
        $result = $this->sandbox->npm($workspace, ['install', '--package-lock-only'], true);
        $evidence('Resolve npm update', $result);
        if (!$result['passed']) {
            throw new \RuntimeException('npm could not resolve the security update.');
        }

        return $plan['files'];
    }

    public function version(string $workspace, string $package): ?string
    {
        $lock = json_decode(file_get_contents($workspace.'/package-lock.json'), true, flags: JSON_THROW_ON_ERROR);
        if (!in_array($lock['lockfileVersion'] ?? null, [2, 3], true)) {
            throw new \DomainException('A version 2 or 3 npm lockfile is required.');
        }

        return $lock['packages']['node_modules/'.$package]['version'] ?? null;
    }
}
