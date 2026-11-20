<?php
declare(strict_types=1);

namespace App\Fleet;

use App\Audit\Store;

final class Analysis
{
    public function __construct(private readonly Store $store)
    {
    }

    public function report(): array
    {
        $assets = array_column($this->store->rows('SELECT * FROM assets'), null, 'id');
        $incoming = [];
        $outgoing = [];
        foreach ($this->store->rows('SELECT * FROM asset_links') as $edge) {
            $incoming[$edge['kind']][$edge['target_id']][] = $edge['source_id'];
            $outgoing[$edge['kind']][$edge['source_id']][] = $edge['target_id'];
        }

        $groups = [];
        foreach ($this->store->iterate('SELECT * FROM findings WHERE active = 1') as $finding) {
            $data = $finding['data'];
            $os = in_array($data['type'], ['ubuntu', 'debian'], true);
            $package = $os ? $data['type'].' packages' : $data['package'];
            $key = implode('|', [$data['advisory'], $data['type'], $package]);
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'advisory' => $data['advisory'], 'package' => $package, 'type' => $data['type'],
                    'rank' => 0, 'findings' => [], 'repositories' => [], 'running' => [], 'workloads' => [],
                ];
            }
            $group = &$groups[$key];
            $group['rank'] = max($group['rank'], match ($data['severity']) {
                'CRITICAL' => 4, 'HIGH' => 3, 'MEDIUM' => 2, 'LOW' => 1, default => 0,
            });
            $id = $finding['asset_id'];
            $group['findings'][] = [
                'id' => $finding['id'], 'asset' => $id, 'name' => $assets[$id]['name'] ?? $id,
                'package' => $data['package'], 'version' => $data['version'], 'fixed' => $data['fixed'],
            ];

            // Only an image finding provides direct evidence of affected running containers.
            foreach ($incoming['RUNS'][$id] ?? [] as $container) {
                if (!($assets[$container]['data']['running'] ?? false)) {
                    continue;
                }
                $group['running'][$container] = $assets[$container]['name'];
                foreach ($incoming['HOSTS'][$container] ?? [] as $parent) {
                    foreach ($incoming['HOSTS'][$parent] ?? [] as $workload) {
                        if ('workload' === ($assets[$workload]['kind'] ?? null)) {
                            $group['workloads'][$workload] = $assets[$workload]['name'];
                        }
                    }
                }
            }
            $repos = 'repository' === ($assets[$id]['kind'] ?? null) ? [$id] : [...($outgoing['BUILT_FROM'][$id] ?? []), ...($outgoing['ASSOCIATED_SOURCE'][$id] ?? [])];
            foreach ($repos as $repo) {
                if ('repository' === ($assets[$repo]['kind'] ?? null)) {
                    $group['repositories'][$repo] = $assets[$repo]['name'];
                }
            }
            unset($group);
        }
        foreach ($groups as &$group) {
            $group['fix_available'] = (bool) array_filter($group['findings'], static fn (array $finding): bool => '' !== $finding['fixed']);
            $group['priority'] = $group['rank'] * 100 + min(49, count($group['running'])) * 2 + (int) $group['fix_available'];
        }
        unset($group);
        uasort($groups, static fn (array $a, array $b): int => $b['priority'] <=> $a['priority'] ?: strcmp($a['advisory'], $b['advisory']));

        return [
            'exposure' => array_values($groups),
            'shared' => $this->sharedDependencies($assets),
            'history' => $this->history(),
        ];
    }

    private function sharedDependencies(array $assets): array
    {
        $components = [];
        foreach ($assets as $id => $asset) {
            foreach ($asset['data']['sbom']['components'] ?? [] as $component) {
                $purl = $component['purl'] ?? null;
                if (!is_string($purl) || !str_starts_with($purl, 'pkg:')) {
                    if ('Demo advisories' !== ($asset['data']['scan_source'] ?? null)) {
                        continue;
                    }
                    $purl = 'pkg:composer/'.$component['name'];
                }
                $package = preg_split('/[@?#]/', $purl, 2)[0];
                $version = $component['version'] ?? 'Unknown';
                $components[$package][$id][$version] = true;
            }
        }

        $shared = [];
        foreach ($components as $package => $observed) {
            if (count($observed) < 2) {
                continue;
            }
            $shared[$package] = array_map('array_keys', $observed);
        }
        uasort($shared, static fn (array $a, array $b): int => count($b) <=> count($a));

        return $shared;
    }

    private function history(): array
    {
        $history = ['attempts' => 0, 'verified_patches' => 0, 'deployed' => 0, 'failed' => 0, 'rollbacks' => 0, 'median_seconds_to_running' => null, 'months' => []];
        $runningTimes = [];
        foreach ($this->store->rows('SELECT id, created_at, status, data FROM changes') as $change) {
            ++$history['attempts'];
            $month = substr($change['created_at'], 0, 7);
            $history['months'][$month] ??= ['attempts' => 0, 'verified' => 0, 'deployed' => 0, 'failed' => 0, 'rollbacks' => 0];
            $period = &$history['months'][$month];
            ++$period['attempts'];
            $period['verified'] += (int) isset($change['data']['patch_sha256']);
            $period['deployed'] += (int) (isset($change['data']['deployed_at']) || in_array($change['status'], ['deployed', 'rolled_back'], true));
            $period['failed'] += (int) ('failed' === $change['status']);
            $period['rollbacks'] += (int) ('rolled_back' === $change['status']);
            unset($period);
            if (isset($change['data']['patch_sha256'])) {
                ++$history['verified_patches'];
            }
            $history['failed'] += (int) ('failed' === $change['status']);
            $history['rollbacks'] += (int) ('rolled_back' === $change['status']);
            if ('deployed' === $change['status']) {
                ++$history['deployed'];
                $verifiedAt = $change['data']['deployed_at'] ?? null;
                if ($verifiedAt) {
                    $runningTimes[] = max(0, strtotime($verifiedAt) - strtotime($change['created_at']));
                }
            }
        }
        if ($runningTimes) {
            sort($runningTimes);
            $middle = intdiv(count($runningTimes), 2);
            $history['median_seconds_to_running'] = ($runningTimes[$middle] + $runningTimes[$middle - (1 - count($runningTimes) % 2)]) / 2;
        }

        krsort($history['months']);

        return $history;
    }
}
