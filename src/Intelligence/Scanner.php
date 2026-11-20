<?php
declare(strict_types=1);

namespace App\Intelligence;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Secrets\SecretManagers;
use App\Settings\OperatorSettings;
use Symfony\Component\Filesystem\Filesystem;
use Composer\Semver\Semver;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Process\Process;

final class Scanner
{
    private const DEMO_RULES = [
        'demo/slugger' => ['PP-DEMO-001', '2.0.0', 'HIGH', 'Slugger compatibility update'],
        'demo/clock' => ['PP-DEMO-002', '1.0.1', 'CRITICAL', 'Clock patch release'],
    ];

    public function __construct(
        private readonly Inventory $inventory,
        private readonly Store $store,
        #[Autowire('%env(TRIVY_BINARY)%')] private readonly string $trivy,
        private readonly ?OperatorSettings $operator = null,
        private readonly ?SecretManagers $managers = null,
    ) {
    }

    public function settings(): array
    {
        return ['timeout' => $this->operator?->get('scanner')['timeout'] ?? 180];
    }

    public function repository(string $workspace, string $scratch, bool $demo): array
    {
        $lock = $this->lock($workspace);
        if ($demo) {
            return $this->demo($lock);
        }

        return $this->project($workspace, $scratch, ['composer']);
    }

    public function project(string $workspace, string $scratch, array $profiles): array
    {
        if (!$profiles) {
            throw new \DomainException('The repository has no supported dependency lockfile.');
        }
        $input = $scratch.'/scan-input';
        if (!is_dir($input)) {
            mkdir($input, 0700);
        }
        $expected = [];
        foreach ($profiles as $profile) {
            $files = match ($profile) {
                'composer' => ['composer.json', 'composer.lock'],
                'npm' => ['package.json', 'package-lock.json'],
                'gomod' => ['go.sum', 'go.mod'],
            };
            foreach ($files as $file) {
                if (!is_file($workspace.'/'.$file) || !copy($workspace.'/'.$file, $input.'/'.$file)) {
                    throw new \RuntimeException('Cannot prepare scanner input.');
                }
            }
            $expected[$profile] = $files[1];
        }
        $report = $this->trivy('fs', $input, $scratch);
        foreach ($report['analyzed'] as $target) {
            if (($expected[$target['Type']] ?? null) === basename($target['Target'])) {
                unset($expected[$target['Type']]);
            }
        }
        if ($expected) {
            throw new \RuntimeException('Trivy did not report an analyzed lockfile for every selected ecosystem.');
        }

        return $report;
    }

    public function aptHost(string $root, string $scratch): array
    {
        $os = parse_ini_file($root.'/etc/os-release', scanner_mode: INI_SCANNER_RAW) ?: [];
        $distro = ($os['ID'] ?? '').'/'.($os['VERSION_ID'] ?? '');
        if (!preg_match('#^(?:ubuntu|debian)/[0-9]+(?:\.[0-9]+)*$#D', $distro)) {
            throw new \DomainException('Expected a supported numeric Ubuntu or Debian release.');
        }
        $report = $this->trivy('rootfs', $root, $scratch, ['--distro', $distro]);
        foreach ($report['analyzed'] as $target) {
            if ('os-pkgs' === ($target['Class'] ?? null) && in_array($target['Type'] ?? null, ['ubuntu', 'debian'], true)) {
                return $report;
            }
        }
        throw new \DomainException('Trivy did not analyze the requested APT package database.');
    }

    public function image(string $digest, string $scratch): array
    {
        if (!preg_match('/^(?:[a-z0-9][a-z0-9.\/:_-]*@)?sha256:[a-f0-9]{64}$/D', $digest)) {
            throw new \InvalidArgumentException('Image scanning requires an immutable digest.');
        }

        return $this->trivy('image', $digest, $scratch, ['--image-src', 'docker']);
    }

    public function registryImage(string $reference, string $platform, string $scratch, bool $managedOnly = false): array
    {
        $env = $this->registryEnvironment(explode('/', $reference, 2)[0], $scratch, $managedOnly);

        return $this->trivy('image', $reference, $scratch, ['--image-src', 'remote', '--platform', $platform, '--cache-backend', 'memory'], $env);
    }

    public function registryEnvironment(string $host, string $scratch, bool $managedOnly): array
    {
        $referenceId = $this->operator?->registryReference($host);
        if ($referenceId && $this->managers) {
            $data = $this->managers->bundle($referenceId);
            if (($data['host'] ?? null) !== $host || !is_string($data['username'] ?? null) || !is_string($data['token'] ?? null)
                || '' === $data['username'] || '' === $data['token'] || str_contains($data['username'], ':')) {
                throw new \DomainException('The registry credential must identify this host and include a username and token.');
            }
            $auth = base64_encode($data['username'].':'.$data['token']);
        } else {
            $auth = $managedOnly ? '' : ($this->operator?->registryAuth($host) ?? '');
        }
        $environment = [];
        if ('' !== $auth || $managedOnly) {
            $directory = $scratch.'/docker-config';
            $fs = new Filesystem();
            $fs->mkdir($directory, 0700);
            $fs->dumpFile($directory.'/config.json', Store::json(['auths' => '' === $auth ? new \stdClass() : [$host => ['auth' => $auth]]]));
            chmod($directory.'/config.json', 0600);
            $environment = ['DOCKER_CONFIG' => $directory, 'TRIVY_USERNAME' => false, 'TRIVY_PASSWORD' => false,
                'TRIVY_REGISTRY_TOKEN' => false];
        }

        return $environment;
    }

    public function record(array $asset, array $report, array $extra = []): void
    {
        $this->store->db->transactional(function () use ($asset, $report, $extra): void {
            $this->inventory->findings($asset['id'], $report['source'], $report['findings']);
            $latest = $this->inventory->get($asset['id']);
            $data = array_replace($latest['data'] ?? $asset['data'], $extra, [
                'sbom' => $report['sbom'], 'scan_source' => $report['source'], 'scanned_at' => gmdate(DATE_ATOM),
            ]);
            $this->store->db->update('assets', ['data' => Store::json($data)], ['id' => $asset['id']]);
        });
    }

    public function copyImageLock(string $image, string $path, string $scratch, string $filename = 'composer.lock'): void
    {
        $container = trim((new Process(['docker', 'create', '--entrypoint', '/bin/false', $image], timeout: 30))->mustRun()->getOutput());
        try {
            (new Process(['docker', 'cp', "$container:$path", $scratch.'/'.$filename], timeout: 30))->mustRun();
            $file = $scratch.'/'.$filename;
            if (is_link($file) || !is_file($file) || filesize($file) > 16000000) {
                throw new \DomainException('Expected a regular dependency lockfile in the image.');
            }
        } finally {
            (new Process(['docker', 'rm', $container], timeout: 30))->run();
        }
    }
    public function lock(string $dir): array
    {
        $raw = file_get_contents($dir.'/composer.lock');
        $lock = json_decode(false === $raw ? '' : $raw, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($lock['packages'] ?? null) || !is_array($lock['packages-dev'] ?? null)) {
            throw new \RuntimeException('Composer lockfile has no package inventory.');
        }

        return $lock;
    }

    public function demo(array $lock): array
    {
        $findings = $components = [];
        foreach ([...$lock['packages'], ...$lock['packages-dev']] as $package) {
            $name = $package['name'];
            $components[] = ['type' => 'library', 'name' => $name, 'version' => $package['version']];
            if (isset(self::DEMO_RULES[$name])) {
                [$advisory, $fixed, $severity, $title] = self::DEMO_RULES[$name];
                if (Semver::satisfies($package['version'], '<'.$fixed)) {
                    $findings[] = [
                        'advisory' => $advisory, 'package' => $name, 'version' => $package['version'],
                        'fixed' => $fixed, 'severity' => $severity, 'title' => $title,
                        'target' => 'composer.lock', 'type' => 'composer', 'url' => null, 'cvss' => null,
                    ];
                }
            }
        }

        return ['source' => 'Demo advisories', 'findings' => $findings, 'sbom' => [
            'bomFormat' => 'CycloneDX', 'specVersion' => '1.5', 'version' => 1, 'components' => $components,
        ]];
    }

    private function trivy(string $target, string $subject, string $scratch, array $targetOptions = [], array $environment = []): array
    {
        $config = $scratch.'/trivy.yaml';
        $ignore = $scratch.'/trivy.ignore';
        file_put_contents($config, "{}\n");
        file_put_contents($ignore, '');
        $common = [$this->trivy, '--config', $config, $target, '--no-progress', '--ignorefile', $ignore];
        $options = ['--offline-scan', ...$targetOptions];
        $timeout = $this->settings()['timeout'];
        $raw = (new Process([
            ...$common, ...$options, '--timeout', $timeout.'s', '--scanners', 'vuln', '--format', 'json', '--exit-code', '0', '--', $subject,
        ], $scratch, $environment, timeout: $timeout + 10))->mustRun()->getOutput();
        $scan = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        $json = $scratch.'/scan-report.json';
        file_put_contents($json, $raw);
        $sbom = $this->jsonProcess([$this->trivy, 'convert', '--format', 'cyclonedx', '--', $json], $scratch);
        if (!isset($scan['SchemaVersion']) || 'CycloneDX' !== ($sbom['bomFormat'] ?? null)) {
            throw new \RuntimeException('Trivy returned an unrecognized report.');
        }

        $findings = [];
        foreach ($scan['Results'] ?? [] as $result) {
            foreach ($result['Vulnerabilities'] ?? [] as $item) {
                $url = $item['PrimaryURL'] ?? null;
                $scores = array_column($item['CVSS'] ?? [], 'V3Score');
                $findings[] = [
                    'advisory' => $item['VulnerabilityID'], 'package' => $item['PkgName'],
                    'version' => $item['InstalledVersion'], 'fixed' => $item['FixedVersion'] ?? '',
                    'severity' => strtoupper($item['Severity'] ?? 'UNKNOWN'),
                    'title' => $item['Title'] ?? $item['VulnerabilityID'],
                    'target' => $result['Target'], 'type' => $result['Type'],
                    'url' => is_string($url) && preg_match('#^https?://#i', $url) ? $url : null,
                    'cvss' => $scores ? max($scores) : null,
                ];
            }
        }

        return ['source' => 'Trivy', 'findings' => $findings, 'sbom' => $sbom, 'analyzed' => $scan['Results'] ?? []];
    }

    private function jsonProcess(array $args, string $directory): array
    {
        $process = new Process($args, $directory, timeout: 180);

        return json_decode($process->mustRun()->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    }
}
