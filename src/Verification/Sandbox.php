<?php
declare(strict_types=1);

namespace App\Verification;

use App\Settings\OperatorSettings;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

final class Sandbox
{
    public function __construct(
        #[Autowire('%env(WORKER_IMAGE)%')] private readonly string $image,
        #[Autowire('%env(WORKER_RESOLVER_NETWORK)%')] private readonly string $resolverNetwork,
        private readonly OperatorSettings $operator,
    ) {
    }

    public function settings(): array
    {
        return $this->operator->get('worker') + ['image' => $this->image, 'network' => $this->resolverNetwork];
    }

    public function composer(string $workspace, array $args, bool $write, bool $demo): array
    {
        return $this->run(
            $workspace,
            ['composer', '--no-ansi', '--no-interaction', '--no-plugins', '--no-scripts', ...$args],
            $write,
            $write && !$demo ? $this->settings()['network'] : 'none',
        );
    }

    public function npm(string $workspace, array $args, bool $write = false): array
    {
        return $this->run($workspace, [
            'npm', '--ignore-scripts', '--no-audit', '--no-fund', '--userconfig=/dev/null', '--fetch-retries=0', '--fetch-timeout=30000', ...$args,
        ], $write, $write ? $this->settings()['network'] : 'none');
    }

    public function go(string $workspace, string $module, string $cache, array $args): array
    {
        if (!is_dir($cache) && !mkdir($cache, 0700, true)) {
            throw new \RuntimeException('Could not create the isolated Go cache.');
        }

        return $this->run($workspace, ['go', '-C', $module, ...$args],
            network: $args === ['mod', 'download'] ? $this->settings()['network'] : 'none', goCache: $cache);
    }

    public function npmForImage(string $workspace, string $image, string $network, array $args): array
    {
        return $this->run($workspace, [
            'npm', '--ignore-scripts', '--no-audit', '--no-fund', '--userconfig=/dev/null', '--fetch-retries=0', '--fetch-timeout=30000', ...$args,
        ], true, $network, $image);
    }

    public function tests(string $workspace): array
    {
        return $this->run($workspace, [
            'php', '/tools/vendor/bin/phpunit', '--do-not-cache-result', '--colors=never',
            '--fail-on-empty-test-suite', '--fail-on-warning',
        ]);
    }

    public function analysis(string $workspace): array
    {
        return $this->run($workspace, [
            'php', '/tools/vendor/bin/phpstan', 'analyse', '--no-progress', '--no-ansi', '--memory-limit=384M',
        ]);
    }

    public function binary(string $workspace, string $image, string $script, string $output, bool $write): array
    {
        return $this->run($workspace, ['./'.$script, './'.$output], $write, image: $image, entrypoint: '/bin/sh');
    }

    private function run(string $workspace, array $command, bool $write = false, string $network = 'none', ?string $image = null, ?string $entrypoint = null, ?string $goCache = null): array
    {
        $name = 'patchrocket-job-'.bin2hex(random_bytes(10));
        $uid = posix_geteuid();
        $gid = posix_getegid();
        if (0 === $uid) {
            throw new \RuntimeException('Run the worker as a non-root operating system user.');
        }
        $memory = null === $image ? '512m' : '1g';
        if ('none' !== $network) {
            $driver = (new Process(['docker', 'network', 'inspect', '--format', '{{.Driver}}', '--', $network], timeout: 10))->mustRun()->getOutput();
            if ('bridge' !== trim($driver)) {
                throw new \DomainException('Dependency resolution requires a dedicated bridge network or none.');
            }
        }
        $mount = 'type=bind,source='.$workspace.',target=/app'.($write ? '' : ',readonly');
        $process = new Process([
            'docker', 'run', '--rm', '--pull=never', '--name', $name, '--init',
            '--network', $network, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--memory='.$memory, '--memory-swap='.$memory, '--cpus=1.5', '--pids-limit=128',
            '--ulimit', 'fsize=134217728:134217728',
            '--user', "$uid:$gid", '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
            '--env', 'HOME=/tmp', '--env', 'COMPOSER_HOME=/tmp/composer',
            '--env', 'COMPOSER_VENDOR_DIR=/app/vendor', '--env', 'COMPOSER_AUTH={}',
            ...($goCache ? ['--mount', 'type=bind,source='.$goCache.',target=/go-cache',
                '--env', 'GOCACHE=/go-cache/build', '--env', 'GOMODCACHE=/go-cache/mod',
                '--env', 'GOPATH=/go-cache', '--env', 'GOTOOLCHAIN=local', '--env', 'GOWORK=off'] : []),
            '--workdir', '/app', '--mount', $mount, ...($entrypoint ? ['--entrypoint', $entrypoint] : []),
            $image ?? $this->settings()['image'], ...$command,
        ], timeout: 120);
        $log = '';
        try {
            $exit = $process->run(static function (string $type, string $chunk) use (&$log, $process): void {
                $log = substr($log.$chunk, -12000);
                $process->clearOutput();
                $process->clearErrorOutput();
            });
        } catch (ProcessTimedOutException) {
            (new Process(['docker', 'rm', '-f', $name], timeout: 15))->run();
            $exit = 124;
            $log .= "\nThe sandbox exceeded its 120-second limit.";
        }

        return ['passed' => 0 === $exit, 'exit' => $exit, 'log' => trim($log)];
    }
}
