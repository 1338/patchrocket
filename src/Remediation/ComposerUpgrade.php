<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Intelligence\Scanner;
use App\Verification\Sandbox;
use Composer\Semver\Semver;

final class ComposerUpgrade implements Strategy
{
    public function __construct(private readonly Sandbox $sandbox, private readonly Scanner $scanner)
    {
    }

    public function plan(array $finding, array $options): array
    {
        if ('composer' !== $finding['type'] || !preg_match('#^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$#D', $finding['package'])) {
            throw new \DomainException('Choose a Composer package finding.');
        }
        $candidates = array_filter(
            preg_split('/\s*,\s*/', trim($finding['fixed'])),
            static fn (string $v): bool => 1 === preg_match('/^v?\d+(?:\.\d+){1,3}$/D', $v)
                && Semver::satisfies($finding['version'], '<'.$v),
        );
        $fixed = Semver::sort($candidates)[0] ?? null;
        if (null === $fixed) {
            throw new \DomainException('The advisory has no supported fixed version above the installed version.');
        }

        return [
            'package' => $finding['package'], 'installed' => $finding['version'], 'fixed' => $fixed,
            'files' => ['composer.json', 'composer.lock'],
            'checks' => ['Composer validate', 'PHPUnit', 'PHPStan', 'Dependency rescan'],
        ];
    }

    public function apply(string $workspace, array $plan, bool $demo, callable $evidence): array
    {
        $manifest = $workspace.'/composer.json';
        $definition = json_decode(file_get_contents($manifest), true, flags: JSON_THROW_ON_ERROR);
        $package = $plan['package'];
        $fixed = $plan['fixed'];
        $versions = array_column([
            ...$this->scanner->lock($workspace)['packages'], ...$this->scanner->lock($workspace)['packages-dev'],
        ], 'version', 'name');
        if (!isset($versions[$package]) || !Semver::satisfies($versions[$package], '='.$plan['installed'])) {
            throw new \RuntimeException('The snapshot no longer matches the finding.');
        }
        // Only alter a direct requirement if its existing constraint excludes the security fix.
        foreach (['require', 'require-dev'] as $section) {
            $constraint = $definition[$section][$package] ?? null;
            if ($constraint && !Semver::satisfies($fixed, $constraint)) {
                $definition[$section][$package] = $fixed;
                file_put_contents($manifest, json_encode($definition, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
                break;
            }
        }
        $result = $this->sandbox->composer($workspace, [
            'update', $package.':'.$fixed, '--with-all-dependencies', '--prefer-dist', '--no-progress', '--no-audit',
        ], true, $demo);
        $evidence('Resolve dependency update', $result);
        if (!$result['passed']) {
            throw new \RuntimeException('Composer could not resolve the security update.');
        }

        return $plan['files'];
    }
}
