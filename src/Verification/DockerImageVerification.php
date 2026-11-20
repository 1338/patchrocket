<?php
declare(strict_types=1);

namespace App\Verification;

use App\Intelligence\Scanner;
use Symfony\Component\Process\Process;

final class DockerImageVerification
{
    public function __construct(private readonly Scanner $scanner)
    {
    }

    public function verify(string $workspace, string $scratch, array $plan, callable $evidence): array
    {
        $suffix = bin2hex(random_bytes(10));
        // This strategy changes only the container base. Application package checks
        // belong to dependency remediations, regardless of the repository's languages.
        $tag = 'patchrocket-verification:'.$suffix;
        $iid = $scratch.'/verified-image.id';
        $dockerfile = $workspace.'/'.$plan['files'][0];
        $original = file_get_contents($dockerfile);
        if (!str_contains($original, 'FROM '.$plan['fixed'])) {
            throw new \DomainException('The verified Dockerfile must reference the pinned candidate base.');
        }
        try {
            $this->required('Local container build', $this->docker(['build', '--network=none', '--platform='.$plan['platform'],
                '--file', $dockerfile, '--tag', $tag, '--iidfile', $iid, '--', $workspace.'/'.$plan['module']], 180), $evidence);
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
