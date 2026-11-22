<?php
declare(strict_types=1);

namespace App\Verification;

use App\Intelligence\Scanner;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class DockerImageVerification
{
    public function __construct(
        private readonly Scanner $scanner,
        private readonly Sandbox $sandbox,
    ) {
    }

    public function verify(string $workspace, string $scratch, array $plan, callable $evidence): array
    {
        $suffix = bin2hex(random_bytes(10));
        $tag = 'patchrocket-verification:'.$suffix;
        $iid = $scratch.'/verified-image.id';
        $dockerfile = $workspace.'/'.$plan['files'][0];
        $original = file_get_contents($dockerfile);
        if (!str_contains($original, 'FROM '.$plan['fixed'])) {
            throw new \DomainException('The verified Dockerfile must reference the pinned candidate base.');
        }
        $context = $workspace.'/'.$plan['module'];
        if (!file_exists($context.'/dist') && preg_match('~^\h*COPY\h+(?:\./)?dist/?\h+~mi', $original)) {
            $this->buildFrontend($workspace, $scratch, $plan['module'], $evidence);
        }
        try {
            $this->required('Local container build', $this->docker(['build', '--network=none', '--platform='.$plan['platform'],
                '--file', $dockerfile, '--tag', $tag, '--iidfile', $iid, '--', $context], 180), $evidence);
            $digest = trim(file_get_contents($iid));
            $script = <<<'SH'
test "$(id -u)" -ne 0
nginx -t
version="$(nginx -v 2>&1)"
package="$(awk '/^P:nginx$/ { installed=1; next } installed && /^V:/ { print substr($0, 3); exit }' /lib/apk/db/installed)"
test -n "$package"
test "$(apk version -t "$package" "$1")" != "<"
test "$version" = "nginx version: nginx/${package%-r*}"
printf '%s\n' "$version" "Installed nginx package: $package"
SH;
            $runtime = $this->docker(['run', '--rm', '--pull=never', '--network=none', '--read-only',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--memory=128m', '--pids-limit=32', '--entrypoint', '/bin/sh', $digest, '-ec', $script, 'verify', $plan['package_fixed']], 30);
            $this->required('nginx configuration and package', $runtime, $evidence);

            $scan = $this->scanner->image($digest, $scratch);
            $scannedAlpine = array_filter($scan['analyzed'], static fn (array $target): bool =>
                ('os-pkgs' === ($target['Class'] ?? null) && 'alpine' === ($target['Type'] ?? null)));
            $stillPresent = array_values(array_filter($scan['findings'], static fn (array $finding): bool =>
                'nginx' === $finding['package'] && in_array($finding['advisory'], $plan['advisories'], true)));
            $this->required('Rebuilt image scan', [
                'passed' => (bool) $scannedAlpine && !$stillPresent,
                'log' => sprintf('Trivy scanned %s. %d of %d selected nginx advisories remain.', $digest, count($stillPresent), count($plan['advisories'])),
                'findings' => $stillPresent,
            ], $evidence);

            return ['digest' => $digest, 'advisories' => $plan['advisories'], 'runtime' => $runtime['log']];
        } finally {
            $this->docker(['image', 'rm', $tag], 30);
        }
    }

    private function buildFrontend(string $workspace, string $scratch, string $module, callable $evidence): void
    {
        if (!is_file($workspace.'/package-lock.json') || !is_file($workspace.'/'.$module.'/package.json')) {
            throw new \DomainException('The Dockerfile copies dist, but the repository has no npm workspace lockfile and module manifest.');
        }
        $settings = $this->sandbox->settings();
        $filesystem = new Filesystem();
        $build = $scratch.'/frontend-build';
        // Keep npm outputs and any changes made by build scripts outside the verified Docker context.
        $filesystem->mirror($workspace, $build);
        $this->required('Frontend dependency install', $this->sandbox->npmForImage(
            $build, $settings['image'], $settings['network'], ['ci'],
        ), $evidence);
        $result = $this->sandbox->npmForImage($build, $settings['image'], 'none', ['run', 'build', '--workspace=./'.$module]);
        $this->required('Frontend workspace build', $result, $evidence);

        $dist = $build.'/'.$module.'/dist';
        if (is_link($build.'/'.$module) || is_link($dist) || !is_dir($dist)) {
            throw new \DomainException('The npm workspace build did not produce a regular, non-empty dist directory.');
        }
        $entries = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dist, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST,
        );
        $hasFiles = false;
        foreach ($entries as $entry) {
            if ($entry->isLink() || (!$entry->isFile() && !$entry->isDir())) {
                throw new \DomainException('The npm workspace build produced a non-regular entry in dist.');
            }
            $hasFiles = $hasFiles || $entry->isFile();
        }
        if (!$hasFiles) {
            throw new \DomainException('The npm workspace build produced an empty dist directory.');
        }
        $destination = $workspace.'/'.$module.'/dist';
        $filesystem->mirror($dist, $destination);
        $filesystem->chmod($destination, 0755);
        foreach ($entries as $entry) {
            $target = $destination.substr($entry->getPathname(), strlen($dist));
            $filesystem->chmod($target, $entry->isDir() ? 0755 : 0644);
        }
    }

    private function required(string $label, array $result, callable $evidence): void
    {
        $evidence($label, $result);
        if (!$result['passed']) {
            throw new \DomainException($label.' failed. Review the recorded check.');
        }
    }

    private function docker(array $arguments, int $timeout): array
    {
        $process = new Process(['docker', ...$arguments], timeout: $timeout);
        $log = '';
        try {
            $exit = $process->run(static function (string $type, string $chunk) use ($process, &$log): void {
                $log = substr($log.$chunk, -10000);
                $process->clearOutput();
                $process->clearErrorOutput();
            });
        } catch (\Symfony\Component\Process\Exception\ProcessTimedOutException) {
            $log .= "\nThe verification command exceeded its time limit.";
            $exit = 124;
        }

        return ['passed' => 0 === $exit, 'exit' => $exit, 'log' => trim($log)];
    }
}
