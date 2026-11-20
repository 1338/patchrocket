<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Intelligence\Scanner;
use App\Settings\OperatorSettings;
use Symfony\Component\Process\Process;

final class HarborRelease
{
    public function __construct(private readonly Scanner $scanner, private readonly OperatorSettings $settings)
    {
    }

    public function resolve(string $image, string $revision, string $platform, string $scratch): ?array
    {
        if (!preg_match('~^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]+$~D', $image)
            || !preg_match('/^[a-f0-9]{40}$/D', $revision) || !preg_match('~^linux/[a-z0-9]+(?:/v[0-9]+)?$~D', $platform)) {
            throw new \DomainException('The release requires an observed registry repository, Git commit and platform.');
        }
        $host = explode('/', $image, 2)[0];
        if (!$this->settings->registryReference($host)) {
            throw new \DomainException('Configure a managed pull credential for '.$host.' in Delivery integrations.');
        }
        return $this->artifact($image, $image.':'.$revision, $platform, $scratch, $revision);
    }

    public function upstream(string $reference, string $platform, string $scratch): array
    {
        if (!preg_match('~^([a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]+)(?::[a-zA-Z0-9_.-]+)?@(sha256:[a-f0-9]{64})$~D', $reference, $parts)
            || !preg_match('~^linux/[a-z0-9]+(?:/v[0-9]+)?$~D', $platform)) {
            throw new \DomainException('Enter a complete upstream image with its SHA-256 digest and the observed Linux platform.');
        }
        $artifact = $this->artifact($parts[1], $reference, $platform, $scratch, null);
        if (!$artifact || $parts[2] !== $artifact['digests'][0]) {
            throw new \DomainException('The upstream registry did not resolve the requested image digest.');
        }

        return $artifact;
    }

    private function artifact(string $image, string $reference, string $platform, string $scratch, ?string $revision): ?array
    {
        $host = explode('/', $image, 2)[0];
        $env = $this->scanner->registryEnvironment($host, $scratch, true);
        $buildx = $this->buildx($env);
        $manifest = $this->inspect($buildx, $reference, 'Manifest', $env, true);
        if (null === $manifest) {
            return null;
        }
        $root = self::digest($manifest['digest'] ?? null);
        $digest = $root;
        if (isset($manifest['manifests'])) {
            $entries = array_filter($manifest['manifests'], static function (array $entry) use ($platform): bool {
                $target = $entry['platform'] ?? [];

                return $platform === implode('/', array_filter([$target['os'] ?? '', $target['architecture'] ?? '', $target['variant'] ?? '']));
            });
            if (1 !== count($entries)) {
                throw new \DomainException('Harbor did not identify one release manifest for the tracked platform.');
            }
            $digest = self::digest(reset($entries)['digest'] ?? null);
        }
        $config = $this->inspect($buildx, $image.'@'.$digest, 'Image', $env);
        [$os, $arch] = explode('/', $platform);
        if (($config['os'] ?? null) !== $os || ($config['architecture'] ?? null) !== $arch) {
            throw new \DomainException('The Harbor image platform does not match the observed workload.');
        }
        if (null !== $revision && ($config['config']['Labels']['org.opencontainers.image.revision'] ?? null) !== $revision) {
            throw new \DomainException('The Harbor image revision label does not match the tracked source commit.');
        }

        return ['image' => $image.'@'.$digest, 'tag' => $reference, 'digests' => array_values(array_unique([$root, $digest]))];
    }

    private static function digest(mixed $digest): string
    {
        if (!is_string($digest) || !preg_match('/^sha256:[a-f0-9]{64}$/D', $digest)) {
            throw new \DomainException('Harbor did not return an immutable image digest.');
        }

        return $digest;
    }

    private function buildx(#[\SensitiveParameter] array $env): array
    {
        $command = ['docker', 'buildx'];
        if (0 === (new Process([...$command, 'version'], env: $env, timeout: 10))->run()) {
            return $command;
        }

        // A per-user plugin may live in the regular Docker config directory.
        // Use the CLI's plugin path with the isolated credential environment.
        $process = new Process(['docker', 'info', '--format', '{{range .ClientInfo.Plugins}}{{if eq .Name "buildx"}}{{println .Path}}{{end}}{{end}}'], timeout: 10);
        $status = $process->run();
        $path = trim($process->getOutput());
        if (0 !== $status || !str_starts_with($path, '/') || basename($path) !== 'docker-buildx' || !is_file($path) || !is_executable($path)) {
            throw new \DomainException('Could not find Docker Buildx for the managed registry check.');
        }

        return [$path];
    }

    private function inspect(array $buildx, string $image, string $field, #[\SensitiveParameter] array $env, bool $allowMissing = false): ?array
    {
        $process = new Process([...$buildx, 'imagetools', 'inspect', '--format', '{{json .'.$field.'}}', $image], env: $env, timeout: 45);
        try {
            $status = $process->run();
            if (0 === $status) {
                $result = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
                if (is_array($result)) {
                    return $result;
                }
            } elseif ($allowMissing && preg_match('/manifest unknown|not found/i', $process->getErrorOutput())) {
                return null;
            }
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface | \JsonException) {
            // Registry details may include credentials.
        }
        throw new \DomainException('Could not inspect the Harbor image. Check registry access and Docker Buildx.');
    }
}
