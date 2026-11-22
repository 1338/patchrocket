<?php
declare(strict_types=1);

namespace App\Settings;

use App\Asset\Inventory;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Discovery\HostCollector;
use App\Discovery\DeploymentProvenance;
use App\Discovery\DiscoveryResult;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\Infrastructure;
use App\Discovery\KubernetesConnectionProbe;
use App\Discovery\Repository;
use App\Intelligence\AssetScans;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final class InventoryWorker
{
    public function __construct(
        private readonly Connections $connections,
        private readonly HostCollector $hosts,
        private readonly Infrastructure $infrastructure,
        private readonly Repository $repositories,
        private readonly AssetScans $scans,
        private readonly ConnectionCredentials $credentials,
        private readonly Inventory $inventory,
        private readonly ManagedGit $git,
        private readonly DeploymentProvenance $provenance,
        private readonly ConnectionDeliveryDiscovery $delivery,
        private readonly KubernetesConnectionProbe $kubernetesProbe,
    ) {
    }

    public function __invoke(RunInventory $run): void
    {
        $row = $this->connections->get($run->connection);
        if (!$row || ($row['data']['token'] ?? null) !== $run->token || ($row['data']['status'] ?? null) !== 'queued') {
            return;
        }
        $data = $row['data'];
        if (!$this->connections->update($row, array_replace($data, ['status' => 'running']))) {
            return;
        }
        $failedImages = [];
        $discoveryAsset = null;
        try {
            $result = 'delivery' === $run->action ? $this->delivery->discover($row) : $this->collect($row['kind'], $data, $run->action);
            if ($result instanceof DiscoveryResult) {
                $discoveryAsset = $result->assetId;
                $result = $result->summary;
            }
            $status = 'complete';
        } catch (\DomainException|\InvalidArgumentException $error) {
            $result = $error->getMessage();
            $status = 'failed';
            if ($error instanceof ClusterImageScanFailure) {
                $failedImages = $error->imageIds;
            }
        } catch (\Throwable) {
            $result = 'Discovery or scanning failed. Check worker access and the connection settings.';
            $status = 'failed';
        }
        $latest = $this->connections->get($run->connection);
        if ($latest && ($latest['data']['token'] ?? null) === $run->token) {
            $finished = time();
            $finishedAt = gmdate(DATE_ATOM, $finished);
            $this->connections->update($latest, array_replace($latest['data'], [
                'status' => $status, 'result' => $result, 'finished_at' => $finishedAt,
                ...('scan' === $run->action ? ['last_scan' => ['status' => $status, 'finished_at' => $finishedAt]
                    + (isset($data['scan_after_package_update']) ? ['after_package_update' => $data['scan_after_package_update']] : [])
                    + ('failed' === $status ? ['failure_reason' => $result] : [])
                    + ($failedImages ? ['failed_images' => $failedImages] : [])] : []),
                ...('discover' === $run->action ? ['last_discovery' => ['status' => $status, 'finished_at' => $finishedAt, 'result' => $result]
                    + ($discoveryAsset ? ['asset_id' => $discoveryAsset] : [])] : []),
                ...('cluster' === $row['kind'] && 'discover' === $run->action && 'complete' === $status
                    ? ['last_discovery_at' => $finishedAt] : []),
                'next_at' => $run->action === 'scan' && !empty($latest['data']['interval'])
                    ? $finished + $latest['data']['interval'] * 60
                    : ($latest['data']['next_at'] ?? 0),
            ]));
        }
    }

    private function collect(string $kind, array $data, string $action): string|DiscoveryResult
    {
        $scan = 'scan' === $action;
        $target = $data['target'];
        $repo = ($data['repository'] ?? '') ?: null;
        switch ($kind) {
            case 'vm':
                if (!str_contains($target, '@')) {
                    throw new \DomainException('Managed VMs require an explicit SSH user@host.');
                }

                return $this->credentials->ssh($data['credential'] ?? '', function (array $options) use ($data, $scan, $target): string|DiscoveryResult {
                    if ($scan) {
                        return $this->scans->linuxSsh($this->hosts, $target, $options)[1].' findings from the host package scan.';
                    }
                    $host = $this->hosts->ssh($target, $options);
                    if (!empty($data['docker_inventory'])) {
                        $containers = $this->hosts->docker($target, $options, !empty($data['docker_sudo']));

                        return new DiscoveryResult($containers.' remote Docker containers discovered.', $host);
                    }

                    return new DiscoveryResult('Host inventory collected.', $host);
                }, ($data['port'] ?? '') ?: null);
            case 'cluster':
                if ('argo' === $action) {
                    $namespace = $data['argo_namespace'] ?? '';
                    $apps = $this->credentials->kubernetes(Connections::argoCredential($data), $target, fn (string $config): array =>
                        $this->infrastructure->argoApplications($target, $namespace, $config));

                    return $this->provenance->observe($target, $namespace, $apps).' Argo CD applications observed.';
                }
                if (!empty($data['host_asset']) && 'linux' !== ($this->inventory->get($data['host_asset'])['kind'] ?? null)) {
                    throw new \DomainException('The linked VM must exist in inventory.');
                }
                $namespaces = Connections::clusterNamespaces($data);
                $discover = function (string $config) use ($target, $namespaces, $repo): array {
                    if (null === $namespaces) {
                        return $this->infrastructure->kubernetesAll($target, $config);
                    }
                    $counts = [];
                    foreach ($namespaces as $namespace) {
                        $counts[$namespace] = $this->infrastructure->kubernetes($target, $namespace, $repo, $config);
                    }

                    return $counts;
                };
                $counts = isset($data['credential_mode'])
                    ? $this->kubernetesProbe->withVerifiedConnection([
                        'target' => $target, 'credentialMode' => $data['credential_mode'], 'credential' => $data['credential'],
                        'namespaceMode' => null === $namespaces ? 'all' : 'selected', 'namespaces' => $namespaces ?? [],
                    ], $discover)
                    : $this->credentials->kubernetes($data['credential'] ?? '', $target, $discover);
                $total = array_sum($counts);
                $this->provenance->refresh($target);
                $cluster = Inventory::assetId('cluster', $target);
                if (!empty($data['host_asset'])) {
                    $this->inventory->link($data['host_asset'], 'HOSTS', $cluster, 'Operator association');
                }

                if (!$scan) {
                    $asset = match (count($counts)) {
                        0 => null,
                        1 => Inventory::assetId('namespace', $target.'/'.array_key_first($counts)),
                        default => $cluster,
                    };

                    return new DiscoveryResult("$total workloads discovered.", $asset);
                }
                $registries = preg_split('/[\s,]+/', $data['registries'] ?? '', flags: PREG_SPLIT_NO_EMPTY);
                if (!$registries) {
                    throw new \DomainException('Add explicit registry hostnames to scan images for this connection.');
                }
                $scopes = array_map(static fn (string|int $namespace): string => $target.'/'.$namespace, array_keys($counts));
                $targets = iterator_to_array($this->scans->runningImages($registries, null, false, scopes: $scopes));
                $success = 0;
                $failedImages = [];
                foreach (array_keys($targets) as $id) {
                    try {
                        $this->scans->observedImage($id, ($data['platform'] ?? '') ?: 'linux/amd64', true);
                        ++$success;
                    } catch (\Exception) {
                        $failedImages[] = $id;
                    }
                }

                $discovered = $total.' '.(1 === $total ? 'workload' : 'workloads').' discovered.';
                if ($failedImages) {
                    throw new ClusterImageScanFailure(sprintf(
                        '%s %d of %d image scans failed. Check registry access and scanner availability, then retry.',
                        $discovered, count($failedImages), count($targets),
                    ), $failedImages);
                }
                if (0 === $success) {
                    return "$discovered No new or previously failed running images matched the configured registries.";
                }

                return $discovered.' '.$success.' '.(1 === $success ? 'image scan' : 'image scans').' completed.';
            case 'docker':
                $docker = $this->infrastructure->dockerInventory('' === $target ? null : $target, $repo, ($data['context'] ?? '') ?: null);

                return new DiscoveryResult($docker['containers'].' containers discovered.', $docker['host']);
            case 'registry':
                $id = $this->scans->registerRegistryImage($target, $data['platform'] ?: 'linux/amd64', $repo);

                return $scan ? $this->scans->scan($id, managedOnly: true).' image findings.' : new DiscoveryResult('Registry image registered.', $id);
            case 'repository':
                $files = preg_split('/\s+/', $data['editable'], flags: PREG_SPLIT_NO_EMPTY);
                $register = function (string $path) use ($files, $data, $scan, $target): string|DiscoveryResult {
                    $id = $this->repositories->register($path, $files, false, $data['subdirectory'] ?: null,
                        str_starts_with($target, 'https://') ? $target : null, ($data['role'] ?? '') ?: null, ($data['infra_context'] ?? '') ?: null,
                        $data['canonical_url'] ?? null);

                    if (!$scan) {
                        return new DiscoveryResult('Repository registered.', $id);
                    }
                    $count = $this->scans->scan($id);
                    return 'infrastructure' === ($data['role'] ?? '') ? "$count infrastructure declarations and references." : "$count dependency findings.";
                };
                if (str_starts_with($target, 'https://')) {
                    return $this->git->checkout($data['credential'] ?? '', $target, $register);
                }

                return $register($target);
        }
        throw new \DomainException('Unknown connection type.');
    }
}
