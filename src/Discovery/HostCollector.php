<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Asset\Inventory;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Process\Process;

final class HostCollector
{
    public function __construct(
        private readonly Inventory $inventory,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
    ) {
    }

    public function local(): string
    {
        $snapshot = $this->collect(new Process(['sh', $this->project.'/bin/host-inventory'], timeout: 30));

        return $this->save($snapshot['hostname'], $snapshot, 'Local probe');
    }

    public function ssh(string $destination, array $options = []): string
    {
        $process = $this->remoteProcess($destination, file_get_contents($this->project.'/bin/host-inventory'), $options);

        return $this->save('ssh/'.$destination, $this->collect($process), 'SSH probe');
    }

    public function docker(string $destination, array $options = [], bool $sudo = false): int
    {
        $host = hash('sha256', 'linux/ssh/'.$destination);
        if (!$this->inventory->get($host)) {
            throw new \DomainException('Collect Linux inventory for this SSH alias first.');
        }
        $script = <<<'SH'
set -eu
docker_read() {
    __DOCKER_COMMAND__ "$@"
}
ids="$(docker_read container ls --all --quiet --no-trunc)"
format='{"id":{{json .Id}},"name":{{json .Name}},"digest":{{json .Image}},"reference":{{json .Config.Image}},"running":{{json .State.Running}}}'
for id in $ids; do
    docker_read container inspect --format "$format" -- "$id"
    image="$(docker_read container inspect --format '{{.Image}}' -- "$id")"
    docker_read image inspect --format '{{json .RepoDigests}}' -- "$image"
done
SH;
        $script = str_replace('__DOCKER_COMMAND__', $sudo ? 'sudo -n -- docker' : 'docker', $script);
        $output = trim($this->capture($this->remoteProcess($destination, $script."\n", $options), 8000000));
        $lines = '' === $output ? [] : explode("\n", $output);
        if (0 !== count($lines) % 2) {
            throw new \DomainException('The remote Docker inventory response is incomplete.');
        }
        $docker = $this->inventory->asset('docker', 'ssh/'.$destination, $destination);
        $this->inventory->link($host, 'HOSTS', $docker, 'SSH Docker probe');
        foreach (array_chunk($lines, 2) as [$record, $references]) {
            $data = json_decode($record, true, flags: JSON_THROW_ON_ERROR);
            $digests = json_decode($references, true, flags: JSON_THROW_ON_ERROR) ?? [];
            $repository = preg_replace('/(?::[^\/:@]+|@sha256:[a-f0-9]{64})$/D', '', $data['reference']);
            $matches = array_filter($digests, static fn (string $reference): bool => str_starts_with($reference, $repository.'@'));
            $digest = reset($matches) ?: (1 === count($digests) ? $digests[0] : $data['digest']);
            $image = $this->inventory->asset('image', $digest, $data['reference'], [
                'digest' => $digest, 'reference' => $data['reference'], 'repo_digests' => $digests,
            ]);
            $container = $this->inventory->asset('container', 'ssh/'.$destination.'/'.$data['id'], ltrim($data['name'], '/'), [
                'running' => $data['running'], 'image' => $digest, 'reference' => $data['reference'],
                'scope' => 'SSH Docker/'.$destination,
            ]);
            $this->inventory->link($docker, 'HOSTS', $container, 'SSH Docker probe');
            $this->inventory->link($container, 'RUNS', $image, 'SSH Docker probe');
        }

        return intdiv(count($lines), 2);
    }

    public function aptFiles(string $destination, string $root, array $options = []): void
    {
        $script = <<<'SH'
set -eu
test -r /etc/os-release
test -r /var/lib/dpkg/status
base64 -w 0 /etc/os-release
printf '\n'
base64 -w 0 /var/lib/dpkg/status
printf '\n'
SH;
        $output = trim($this->capture($this->remoteProcess($destination, $script."\n", $options), 32000000));
        $lines = explode("\n", $output);
        if (2 !== count($lines)) {
            throw new \DomainException('The remote APT metadata response is incomplete.');
        }
        $os = base64_decode($lines[0], true);
        $packages = base64_decode($lines[1], true);
        if (!$os || !$packages || !preg_match('/^ID="?(?:ubuntu|debian)"?$/mi', $os)) {
            throw new \DomainException('Only Ubuntu and Debian APT metadata is supported by this scanner.');
        }
        $filesystem = new \Symfony\Component\Filesystem\Filesystem();
        $filesystem->dumpFile($root.'/etc/os-release', $os);
        $filesystem->dumpFile($root.'/var/lib/dpkg/status', $packages);
    }

    public function executableDigest(string $path, ?string $destination = null, array $options = []): string
    {
        $script = 'set -eu; export LC_ALL=C; file='.escapeshellarg($path)
            .'; test -f "$file"; test -x "$file"; sha256sum < "$file"';
        $process = null === $destination
            ? new Process(['sh', '-s'], input: $script."\n", timeout: 30)
            : $this->remoteProcess($destination, $script."\n", $options);
        try {
            $output = trim($this->capture($process, 1024));
        } catch (\RuntimeException) {
            throw new \DomainException('Could not read the configured executable. Check the path and host read access.');
        }
        if (!preg_match('/^([a-f0-9]{64})  -$/D', $output, $match)) {
            throw new \DomainException('The host returned an invalid executable digest.');
        }

        return $match[1];
    }

    public function deliveryServices(string $destination, array $options, bool $docker, bool $sudo): array
    {
        $script = <<<'SH'
export LC_ALL=C
if command -v systemctl >/dev/null 2>&1; then
    if units="$(systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null)"; then
        printf 'probe\tsystemd\n'
        printf '%s\n' "$units" | awk '$1 ~ /\.service$/ { print "service\t" $1 }'
    else
        printf 'warning\tSystemd metadata was unavailable\n'
    fi
fi
__DOCKER_INVENTORY__
SH;
        $containers = <<<'SH'
if containers="$(__DOCKER_COMMAND__ container ls --format '{{.Names}}{{"\t"}}{{.Image}}{{"\t"}}{{.Ports}}' 2>/dev/null)"; then
    printf 'probe\tdocker\n'
    printf '%s\n' "$containers" | awk 'NF { print "docker\t" $0 }'
else
    printf 'warning\tDocker metadata was unavailable\n'
fi
SH;
        $containers = str_replace('__DOCKER_COMMAND__', $sudo ? 'sudo -n -- docker' : 'docker', $containers);
        $output = trim($this->capture($this->remoteProcess($destination, str_replace(
            '__DOCKER_INVENTORY__', $docker ? $containers : '', $script,
        )."\n", $options), 1048576));

        return array_map(static fn (string $line): array => explode("\t", $line, 4), explode("\n", $output));
    }

    private function remoteProcess(string $destination, string $script, array $options): Process
    {
        if (!preg_match('/^(?:[a-zA-Z_][a-zA-Z0-9_.-]*@)?[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$/D', $destination)) {
            throw new \InvalidArgumentException('Supply a host alias or a user@host destination.');
        }

        return new Process([
            'ssh', ...$options, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'PermitLocalCommand=no', '-T', '--', $destination, 'sh', '-s',
        ], input: $script, timeout: 45);
    }

    public function import(string $host, string $file): string
    {
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/D', $host) || !is_file($file) || filesize($file) > 8000000) {
            throw new \InvalidArgumentException('Supply a stable host name and a snapshot file up to 8 MB.');
        }

        return $this->save('agent/'.$host, $this->parse(file_get_contents($file)), 'Imported agent snapshot');
    }

    public function parse(string $output): array
    {
        $lines = explode("\n", rtrim($output, "\r\n"));
        if ("PATCHROCKET-HOST\t1" !== array_shift($lines) || 'END' !== array_pop($lines)) {
            throw new \DomainException('The collector did not produce a complete version 1 snapshot.');
        }
        $snapshot = ['components' => []];
        foreach ($lines as $line) {
            $fields = explode("\t", $line);
            if ('package' === $fields[0] && 3 === count($fields) && '' !== $fields[1] && '' !== $fields[2]) {
                $snapshot['components'][$fields[1]] = ['name' => $fields[1], 'version' => $fields[2]];
            } elseif (2 === count($fields) && in_array($fields[0], ['hostname', 'kernel', 'ID', 'VERSION_ID', 'PRETTY_NAME', 'manager', 'collected_at', 'tools'], true)) {
                $snapshot[$fields[0]] = $fields[1];
            } else {
                throw new \DomainException('The host snapshot contains an invalid record.');
            }
        }
        foreach (['hostname', 'kernel', 'manager'] as $field) {
            if (empty($snapshot[$field])) {
                throw new \DomainException('The host snapshot is missing '.$field.'.');
            }
        }
        $snapshot['components'] = array_values($snapshot['components']);

        return $snapshot;
    }

    private function collect(Process $process): array
    {
        return $this->parse($this->capture($process, 8000000));
    }

    private function capture(Process $process, int $limit): string
    {
        $size = 0;
        $process->mustRun(static function (string $type, string $data) use (&$size, $limit): void {
            $size += strlen($data);
            if ($size > $limit) {
                throw new \RuntimeException('The host snapshot exceeded its size limit.');
            }
        });

        return $process->getOutput();
    }

    private function save(string $key, array $snapshot, string $source): string
    {
        $alias = str_starts_with($key, 'ssh/') ? substr($key, 4) : null;

        return $this->inventory->asset('linux', $key, $alias ?? $snapshot['hostname'], [
            'hostname' => $snapshot['hostname'], 'ssh_alias' => $alias,
            'os' => $snapshot['PRETTY_NAME'] ?? 'Linux',
            'distribution' => $snapshot['ID'] ?? null,
            'release' => $snapshot['VERSION_ID'] ?? null,
            'kernel' => $snapshot['kernel'],
            'manager' => $snapshot['manager'],
            'components' => $snapshot['components'],
            'discovery_source' => $source,
            'collected_at' => $snapshot['collected_at'] ?? null, 'tools' => $snapshot['tools'] ?? null,
        ]);
    }
}
