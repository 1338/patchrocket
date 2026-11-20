<?php
declare(strict_types=1);

namespace App\Settings;

use App\Asset\Inventory;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Discovery\HostCollector;
use App\Discovery\DeploymentProvenance;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\Infrastructure;
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
        try {
            $result = 'delivery' === $run->action ? $this->delivery->discover($row) : $this->collect($row['kind'], $data, $run->action);
            $status = 'complete';
        } catch (\DomainException|\InvalidArgumentException $error) {
            $result = $error->getMessage();
            $status = 'failed';
        } catch (\Throwable) {
            $result = 'Discovery or scanning failed. Check worker access and the connection settings.';
            $status = 'failed';
        }
        $latest = $this->connections->get($run->connection);
        if ($latest && ($latest['data']['token'] ?? null) === $run->token) {
            $this->connections->update($latest, array_replace($latest['data'], [
                'status' => $status, 'result' => $result, 'finished_at' => gmdate(DATE_ATOM),
                'next_at' => $run->action === 'scan' && !empty($latest['data']['interval'])
                    ? time() + $latest['data']['interval'] * 60
                    : ($latest['data']['next_at'] ?? 0),
            ]));
        }
    }

    private function collect(string $kind, array $data, string $action): string
    {
        $scan = 'scan' === $action;
        $target = $data['target'];
        $repo = ($data['repository'] ?? '') ?: null;
        switch ($kind) {
            case 'vm':
                if (!str_contains($target, '@')) {
                    throw new \DomainException('Managed VMs require an explicit SSH user@host.');
                }

                return $this->credentials->ssh($data['credential'] ?? '', function (array $options) use ($data, $scan, $target): string {
                    if ($scan) {
                        return $this->scans->linuxSsh($this->hosts, $target, $options)[1].' findings from the host package scan.';
                    }
                    $this->hosts->ssh($target, $options);
                    if (!empty($data['docker_inventory'])) {
                        return $this->hosts->docker($target, $options, !empty($data['docker_sudo'])).' remote Docker containers discovered.';
                    }

                    return 'Host inventory collected.';
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
                $total = $this->credentials->kubernetes($data['credential'] ?? '', $target, fn (string $config): int =>
                    $data['all_namespaces'] ? array_sum($this->infrastructure->kubernetesAll($target, $config))
                    : $this->infrastructure->kubernetes($target, $data['namespace'] ?: 'default', $repo, $config));
                $this->provenance->refresh($target);
                if (!empty($data['host_asset'])) {
                    $this->inventory->link($data['host_asset'], 'HOSTS', hash('sha256', 'cluster/'.$target), 'Operator association');
                }

                if (!$scan) {
                    return "$total workloads discovered.";
                }
                $registries = preg_split('/[\s,]+/', $data['registries'], flags: PREG_SPLIT_NO_EMPTY);
                if (!$registries) {
                    throw new \DomainException('Add explicit registry hostnames to scan images for this connection.');
                }
                $scope = $data['all_namespaces'] ? null : $target.'/'.($data['namespace'] ?: 'default');
                $targets = iterator_to_array($this->scans->runningImages($registries, $scope, false, $target.'/'));
                $success = $failures = 0;
                foreach (array_keys($targets) as $id) {
                    try {
                        $this->scans->observedImage($id, $data['platform'] ?: 'linux/amd64', true);
                        ++$success;
                    } catch (\Exception) {
                        ++$failures;
                    }
                }

                return "$total workloads discovered. $success image scans completed. $failures failed.";
            case 'docker':
                return $this->infrastructure->docker('' === $target ? null : $target, $repo, ($data['context'] ?? '') ?: null).' containers discovered.';
            case 'registry':
                $id = $this->scans->registerRegistryImage($target, $data['platform'] ?: 'linux/amd64', $repo);

                return $scan ? $this->scans->scan($id, managedOnly: true).' image findings.' : 'Registry image registered.';
            case 'repository':
                $files = preg_split('/\s+/', $data['editable'], flags: PREG_SPLIT_NO_EMPTY);
                $register = function (string $path) use ($files, $data, $scan, $target): string {
                    $id = $this->repositories->register($path, $files, false, $data['subdirectory'] ?: null,
                        str_starts_with($target, 'https://') ? $target : null, ($data['role'] ?? '') ?: null, ($data['infra_context'] ?? '') ?: null,
                        $data['canonical_url'] ?? null);

                    if (!$scan) {
                        return 'Repository registered.';
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
