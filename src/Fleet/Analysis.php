<?php
declare(strict_types=1);

namespace App\Fleet;

use App\Asset\Inventory;
use App\Audit\Store;

final class Analysis
{
    public function __construct(private readonly Store $store)
    {
    }

    public function report(bool $includeFindings = true): array
    {
        $digest = $this->store->jsonText('data', 'digest');
        $assets = array_column($this->store->rows("SELECT id, kind, name, $digest AS digest FROM assets"), null, 'id');
        $hosts = $sources = [];
        foreach ($this->store->iterate("SELECT kind, source_id, target_id FROM asset_links
            WHERE kind IN ('HOSTS', 'BUILT_FROM', 'ASSOCIATED_SOURCE')") as $edge) {
            if ('HOSTS' === $edge['kind']) {
                $hosts[$edge['target_id']][] = $edge['source_id'];
            } else {
                $sources[$edge['kind']][$edge['source_id']][] = $edge['target_id'];
            }
        }
        $runningByImage = $runningByDigest = [];
        $observations = Inventory::imageRuntimeObservationsSql($this->store);
        foreach ($this->store->iterate("SELECT id, name, image_id, digest FROM ($observations) observations WHERE running = 1") as $observed) {
            $runningByImage[$observed['image_id']][$observed['id']] = $observed['name'];
            if (null !== $observed['digest']) {
                $runningByDigest[$observed['digest']][$observed['id']] = $observed['name'];
            }
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
                    'rank' => 0, 'findings' => [], 'repositories' => [], 'running' => [], 'workloads' => [], 'fix_available' => false,
                ];
            }
            $group = &$groups[$key];
            $group['rank'] = max($group['rank'], match ($data['severity']) {
                'CRITICAL' => 4, 'HIGH' => 3, 'MEDIUM' => 2, 'LOW' => 1, default => 0,
            });
            $id = $finding['asset_id'];
            $group['fix_available'] = $group['fix_available'] || '' !== $data['fixed'];
            if ($includeFindings) {
                $group['findings'][] = [
                    'id' => $finding['id'], 'asset' => $id, 'name' => $assets[$id]['name'] ?? $id,
                    'package' => $data['package'], 'version' => $data['version'], 'fixed' => $data['fixed'],
                ];
            }

            $containers = $runningByImage[$id] ?? [];
            if ('image' === ($assets[$id]['kind'] ?? null) && null !== $assets[$id]['digest']) {
                $containers += $runningByDigest[$assets[$id]['digest']] ?? [];
            }
            foreach ($containers as $container => $name) {
                if (isset($group['running'][$container])) {
                    continue;
                }
                $group['running'][$container] = $name;
                foreach ($hosts[$container] ?? [] as $parent) {
                    foreach ($hosts[$parent] ?? [] as $workload) {
                        if ('workload' === ($assets[$workload]['kind'] ?? null)) {
                            $group['workloads'][$workload] = $assets[$workload]['name'];
                        }
                    }
                }
            }
            $repos = 'repository' === ($assets[$id]['kind'] ?? null) ? [$id]
                : [...($sources['BUILT_FROM'][$id] ?? []), ...($sources['ASSOCIATED_SOURCE'][$id] ?? [])];
            foreach ($repos as $repo) {
                if ('repository' === ($assets[$repo]['kind'] ?? null)) {
                    $group['repositories'][$repo] = $assets[$repo]['name'];
                }
            }
            unset($group);
        }
        foreach ($groups as &$group) {
            $group['priority'] = $group['rank'] * 100 + min(49, count($group['running'])) * 2 + (int) $group['fix_available'];
        }
        unset($group);
        uasort($groups, static fn (array $a, array $b): int => $b['priority'] <=> $a['priority'] ?: strcmp($a['advisory'], $b['advisory']));

        return [
            'exposure' => array_values($groups),
            'shared' => $this->sharedDependencies(),
            'history' => $this->history(),
        ];
    }

    private function sharedDependencies(): array
    {
        $components = [];
        foreach ($this->store->iterate('SELECT id, data FROM assets') as $asset) {
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
                $components[$package][$asset['id']][$version] = true;
            }
        }

        foreach ($components as $package => &$observed) {
            if (count($observed) < 2) {
                unset($components[$package]);
                continue;
            }
            $observed = array_map('array_keys', $observed);
        }
        unset($observed);
        uksort($components, static fn (string $a, string $b): int =>
            count($components[$b]) <=> count($components[$a]) ?: strcmp($a, $b));

        return $components;
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
