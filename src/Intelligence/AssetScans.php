<?php
declare(strict_types=1);

namespace App\Intelligence;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Discovery\InfrastructureRepository;
use App\Discovery\HostCollector;
use App\Discovery\Repository;

final class AssetScans
{
    public function __construct(
        private readonly Inventory $inventory,
        private readonly Repository $repository,
        private readonly Infrastructure $infrastructure,
        private readonly Scanner $scanner,
        private readonly Store $store,
        private readonly ?InfrastructureRepository $infrastructureRepository = null,
    ) {
    }

    public function registerRegistryImage(string $reference, string $platform, ?string $repository): string
    {
        $registryName = $this->registryName($reference, $platform);
        if (null !== $repository && 'repository' !== ($this->inventory->get($repository)['kind'] ?? null)) {
            throw new \InvalidArgumentException('Supply a registered source repository.');
        }
        $registry = $this->inventory->asset('registry', $registryName, $registryName);
        $image = $this->inventory->asset('image', $reference.'#'.$platform, $reference, [
            'digest' => $reference, 'platform' => $platform, 'origin' => 'registry',
        ]);
        $this->inventory->link($registry, 'HOSTS', $image, 'Registry registration');
        if (null !== $repository) {
            $this->inventory->link($image, 'BUILT_FROM', $repository, 'Operator association');
        }

        return $image;
    }

    public function linuxSsh(HostCollector $hosts, string $destination, array $sshOptions = []): array
    {
        $id = $hosts->ssh($destination, $sshOptions);
        $asset = $this->inventory->get($id);
        if ('APT' !== ($asset['data']['manager'] ?? null)) {
            throw new \DomainException('Only Ubuntu and Debian APT hosts can currently be scanned over SSH.');
        }
        $report = $this->repository->temporary(function (string $scratch) use ($hosts, $destination, $sshOptions): array {
            $root = $scratch.'/rootfs';
            $hosts->aptFiles($destination, $root, $sshOptions);

            return $this->scanner->aptHost($root, $scratch);
        });
        $this->scanner->record($asset, $report);

        return [$id, count($report['findings'])];
    }

    public function observedImage(string $id, string $platform, bool $managedOnly = false): int
    {
        $asset = $this->inventory->get($id);
        if ('image' !== ($asset['kind'] ?? null)) {
            throw new \DomainException('Supply an observed image asset ID.');
        }
        $reference = $asset['data']['digest'] ?? '';
        // Kubernetes runtimes may omit the Docker Hub registry in familiar image names.
        if (!preg_match('#^[^/]*[.:][^/]*/#', $reference)) {
            $reference = 'docker.io/'.(str_contains($reference, '/') ? '' : 'library/').$reference;
        }
        $registryName = $this->registryName($reference, $platform);

        try {
            return $this->repository->temporary(function (string $scratch) use ($asset, $reference, $platform, $registryName, $managedOnly): int {
                $report = $this->scanner->registryImage($reference, $platform, $scratch, $managedOnly);
                $registry = $this->inventory->asset('registry', $registryName, $registryName);
                $this->inventory->link($registry, 'HOSTS', $asset['id'], 'Observed image registry');
                $this->scanner->record($asset, $report, [
                    'platform' => $platform, 'origin' => 'registry', 'registry_reference' => $reference,
                    'scan_attempted_at' => gmdate(DATE_ATOM), 'scan_outcome' => 'complete',
                ]);

                return count($report['findings']);
            });
        } catch (\Exception $error) {
            $latest = $this->inventory->get($id) ?? $asset;
            $data = array_replace($latest['data'], ['scan_attempted_at' => gmdate(DATE_ATOM), 'scan_outcome' => 'failed']);
            $this->store->db->update('assets', ['data' => Store::json($data)], ['id' => $id]);

            throw $error;
        }
    }

    public function runningImages(array $registries, ?string $scope, bool $refresh, ?string $scopePrefix = null): iterable
    {
        if (!$registries || array_filter($registries, static fn (string $name): bool => !preg_match('/^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?$/D', $name))) {
            throw new \InvalidArgumentException('Explicitly select one or more registry hosts.');
        }
        $seen = [];
        foreach ($this->store->iterate(
            "SELECT i.id, i.name, i.data, c.data AS container FROM assets i
              JOIN asset_links r ON r.target_id = i.id AND r.kind = 'RUNS'
              JOIN assets c ON c.id = r.source_id WHERE i.kind = 'image' AND c.kind = 'container'
              ORDER BY i.name, i.id",
        ) as $row) {
            $id = $row['id'];
            $container = json_decode($row['container'], true, flags: JSON_THROW_ON_ERROR);
            if (isset($seen[$id]) || !($container['running'] ?? false) || (null !== $scope && ($container['scope'] ?? '') !== $scope)
                || (null !== $scopePrefix && !str_starts_with($container['scope'] ?? '', $scopePrefix))
                || (!$refresh && ($row['data']['scan_source'] ?? null) && 'failed' !== ($row['data']['scan_outcome'] ?? null))) {
                continue;
            }
            $reference = $row['data']['digest'] ?? '';
            if (!str_contains($reference, '@sha256:')) {
                continue;
            }
            $registry = preg_match('#^[^/]*[.:][^/]*/#', $reference) ? explode('/', $reference, 2)[0] : 'docker.io';
            if (in_array($registry, $registries, true)) {
                $seen[$id] = true;
                yield $id => $row['name'];
            }
        }
    }

    private function registryName(string $reference, string $platform): string
    {
        if (!preg_match('#^([a-z0-9][a-z0-9.-]*(?::[0-9]+)?)/(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*@sha256:[a-f0-9]{64}$#D', $reference, $matches)
            || (!str_contains($matches[1], '.') && !str_contains($matches[1], ':'))
            || !preg_match('#^linux/[a-z0-9]+(?:/v[0-9]+)?$#D', $platform)) {
            throw new \InvalidArgumentException('Supply a fully qualified registry image digest and Linux platform.');
        }
        return $matches[1];
    }

    public function localImage(string $reference, bool $demo): int
    {
        return $this->scan($this->infrastructure->dockerImage($reference), $demo);
    }

    public function scan(string $id, bool $demoImage = false, bool $managedOnly = false): int
    {
        $asset = $this->inventory->get($id);
        if (!in_array($asset['kind'] ?? null, ['repository', 'image'], true)) {
            throw new \DomainException('Supply a registered repository or image.');
        }

        if ('repository' === $asset['kind'] && 'infrastructure' === ($asset['data']['role'] ?? null) && $this->infrastructureRepository) {
            return $this->infrastructureRepository->scan($asset);
        }

        return $this->repository->temporary(function (string $scratch) use ($asset, $demoImage, $managedOnly): int {
            $data = $asset['data'];
            $extra = [];
            if ('repository' === $asset['kind']) {
                $revision = $this->repository->revision($data['path']);
                $snapshot = $this->repository->snapshot($data['path'], $revision, $scratch, $data['subdirectory'] ?? null);
                $profiles = [];
                foreach (['composer' => 'composer.lock', 'npm' => 'package-lock.json', 'gomod' => 'go.sum'] as $profile => $lockfile) {
                    if (is_file($snapshot.'/'.$lockfile)) {
                        $profiles[] = $profile;
                    }
                }
                $report = $data['demo']
                    ? $this->scanner->repository($snapshot, $scratch, true)
                    : $this->scanner->project($snapshot, $scratch, $profiles);
                $extra['revision'] = $revision;
            } elseif ('registry' === ($data['origin'] ?? null)) {
                $report = $this->scanner->registryImage($data['registry_reference'] ?? $data['digest'], $data['platform'], $scratch, $managedOnly);
            } elseif ($demoImage) {
                $this->scanner->copyImageLock($data['digest'], '/fixture/composer.lock', $scratch);
                $report = $this->scanner->demo($this->scanner->lock($scratch));
            } else {
                $report = $this->scanner->image($data['digest'], $scratch);
            }
            $this->scanner->record($asset, $report, $extra);

            return count($report['findings']);
        });
    }
}
