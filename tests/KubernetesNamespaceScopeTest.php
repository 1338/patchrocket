<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\DeliveryDiscovery;
use App\Discovery\DeploymentProvenance;
use App\Discovery\HostCollector;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\AssetScans;
use App\Intelligence\Scanner;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\InventoryWorker;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use App\Settings\RunInventory;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Process\Process;

final class KubernetesNamespaceScopeTest extends TestCase
{
    private const CONNECTION = ['name' => 'West', 'target' => 'west', 'credential' => 'fixture:kube'];
    private Store $store;
    private Connections $connections;
    private RunInventory $queued;

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $bus = $this->createStub(MessageBusInterface::class);
        $bus->method('dispatch')->willReturnCallback(function (RunInventory $run): Envelope {
            $this->queued = $run;

            return new Envelope($run);
        });
        $this->connections = new Connections($this->store, $bus);
    }

    public function testScopeChangesPreserveConnectionSettingsAndRoundTripThroughLegacyForm(): void
    {
        $id = $this->connections->save('cluster', self::CONNECTION + [
            'namespace' => 'old', 'repository' => 'source', 'host_asset' => 'host',
            'registries' => 'registry.example', 'platform' => 'linux/arm64', 'interval' => '15',
        ]);
        $this->connections->saveArgo($id, 'argocd', 'fixture:argo');
        $row = $this->connections->get($id);
        self::assertSame(['old'], Connections::clusterNamespaces($row['data']));
        self::assertTrue($this->connections->update($row, array_replace($row['data'], [
            'next_at' => 123456, 'result' => 'Previous result', 'test_endpoint' => 'https://kube.example',
        ])));
        $previous = $this->connections->get($id)['data'];

        $this->connections->save('cluster', [
            'id' => $id, 'name' => 'West edited', 'namespace_mode' => 'selected',
            'namespaces' => ['payments', 'build', 'build'], 'namespace' => 'stale', 'all_namespaces' => '1',
        ]);
        $selected = $this->connections->get($id)['data'];
        self::assertSame(array_replace($previous, [
            'namespace' => 'build', 'namespace_mode' => 'selected', 'namespaces' => ['build', 'payments'],
        ]), $selected);
        self::assertTrue(Connections::coversNamespace($selected, 'payments'));
        self::assertFalse(Connections::coversNamespace($selected, 'payments-tools'));

        $this->connections->save('cluster', ['id' => $id, 'name' => 'West legacy edit', 'namespace' => 'build']);
        self::assertSame($selected, $this->connections->get($id)['data']);
        $this->connections->save('cluster', ['id' => $id, 'name' => 'West', 'namespace' => 'legacy']);
        $legacy = $this->connections->get($id)['data'];
        self::assertSame(['legacy'], Connections::clusterNamespaces($legacy));
        self::assertArrayNotHasKey('namespaces', $legacy);
        self::assertArrayNotHasKey('namespace_mode', $legacy);

        $this->connections->save('cluster', ['id' => $id, 'name' => 'West', 'namespace_mode' => 'all', 'namespaces' => ['legacy']]);
        $all = $this->connections->get($id)['data'];
        self::assertSame('1', $all['all_namespaces']);
        self::assertSame([], $all['namespaces']);
        self::assertNull(Connections::clusterNamespaces($all));
        self::assertTrue(Connections::coversNamespace($all, 'any'));
        $this->connections->save('cluster', ['id' => $id, 'name' => 'West', 'namespace' => 'default']);
        self::assertSame(['default'], Connections::clusterNamespaces($this->connections->get($id)['data']));
    }

    public static function invalidScopes(): iterable
    {
        yield 'unknown mode' => [['namespace_mode' => 'other', 'namespaces' => ['build']]];
        yield 'empty list' => [['namespace_mode' => 'selected', 'namespaces' => [], 'all_namespaces' => '1']];
        yield 'string list' => [['namespaces' => 'build,payments']];
        yield 'map' => [['namespaces' => ['key' => 'build']]];
        yield 'integer' => [['namespaces' => [42]]];
        yield 'invalid name' => [['namespaces' => ['build', 'PAYMENTS']]];
        yield 'name too long' => [['namespaces' => [str_repeat('a', 64)]]];
        yield 'too many' => [['namespaces' => array_map(static fn (int $number): string => 'ns-'.$number, range(1, 21))]];
    }

    #[DataProvider('invalidScopes')]
    public function testInvalidExplicitScopeIsRejected(array $scope): void
    {
        $this->expectException(DomainException::class);
        $this->connections->save('cluster', self::CONNECTION + $scope);
    }

    public static function inventoryScopes(): iterable
    {
        yield 'selected' => [['namespace_mode' => 'selected', 'namespaces' => ['payments', 'build', 'build']], ['build', 'payments'], ['build', 'payments']];
        yield 'modern all' => [['namespace_mode' => 'all'], ['build', 'payments', 'tools'], ['cluster', 'all']];
        yield 'legacy all' => [['all_namespaces' => '1', 'namespace' => 'tools'], ['build', 'payments', 'tools'], ['cluster', 'all']];
        yield 'legacy named' => [['namespace' => 'tools'], ['tools'], ['tools']];
        yield 'legacy default' => [[], ['default'], ['default']];
    }

    #[DataProvider('inventoryScopes')]
    public function testInventoryQueriesAndRecordsTheEffectiveScope(array $scope, array $expectedNamespaces, array $expectedQueries): void
    {
        $this->withFixture(function (InventoryWorker $worker, Inventory $inventory, string $log) use ($scope, $expectedNamespaces, $expectedQueries): void {
            $repo = $inventory->asset('repository', 'repo', 'Source');
            $host = $inventory->asset('linux', 'host', 'Host');
            $id = $this->connections->save('cluster', self::CONNECTION + $scope + ['repository' => $repo, 'host_asset' => $host]);
            $this->connections->run($id, 'discover');
            $worker($this->queued);

            $data = $this->connections->get($id)['data'];
            self::assertSame('complete', $data['status']);
            self::assertSame(count($expectedNamespaces).' workloads discovered.', $data['result']);
            $discovered = $inventory->get($data['last_discovery']['asset_id']);
            $single = 1 === count($expectedNamespaces);
            self::assertSame($single ? 'namespace' : 'cluster', $discovered['kind']);
            self::assertSame($single ? $expectedNamespaces[0] : 'west', $discovered['name']);
            $namespaces = $this->store->rows("SELECT name, data FROM assets WHERE kind = 'namespace' ORDER BY name");
            self::assertSame($expectedNamespaces, array_column($namespaces, 'name'));
            if (!in_array('all', $expectedQueries, true)) {
                self::assertSame(array_fill(0, count($expectedNamespaces), $repo), array_column(array_column($namespaces, 'data'), 'repository'));
            }
            self::assertSame(1, (int) $this->store->db->fetchOne(
                "SELECT COUNT(*) FROM asset_links WHERE source_id = ? AND kind = 'HOSTS' AND target_id = ?",
                [$host, hash('sha256', 'cluster/west')],
            ));
            $queries = file($log, FILE_IGNORE_NEW_LINES);
            self::assertSame($expectedQueries, array_values(array_unique(array_map(
                static fn (string $line): string => explode(' ', $line, 2)[0], $queries,
            ))));
        });
    }

    public function testDiscoveryAndScanKeepTheirOwnResults(): void
    {
        $this->withFixture(function (InventoryWorker $worker): void {
            $id = $this->connections->save('cluster', self::CONNECTION + [
                'namespace' => 'build', 'registries' => 'fixture.example', 'interval' => 60,
            ]);
            $this->connections->run($id, 'scan');
            $worker($this->queued);
            $scan = $this->connections->get($id)['data'];
            self::assertSame(['status' => 'complete', 'finished_at' => $scan['finished_at']], $scan['last_scan']);
            self::assertStringContainsString('No new or previously failed running images matched', $scan['result']);

            $this->connections->run($id, 'discover');
            $worker($this->queued);
            $discovery = $this->connections->get($id)['data'];
            self::assertSame('discover', $discovery['operation']);
            self::assertSame($scan['last_scan'], $discovery['last_scan']);
            self::assertSame([
                'status' => 'complete', 'finished_at' => $discovery['finished_at'], 'result' => $discovery['result'],
                'asset_id' => hash('sha256', 'namespace/west/build'),
            ], $discovery['last_discovery']);
            $schedule = $this->connections->scheduledScans(time())['rows'][0];
            self::assertSame('complete', $schedule['outcome']);
            self::assertSame($scan['finished_at'], $schedule['checked_at']);

            $this->connections->run($id, 'scan', afterDiscovery: true);
            $worker($this->queued);
            $checklist = $this->connections->discoveryChecklist($id)[0];
            self::assertSame('scan', $checklist['job']['operation']);
            self::assertSame($discovery['last_discovery'], $checklist['discovery']);
            self::assertSame('complete', $checklist['scan']['status']);
            self::assertNull($checklist['scan_blocker']);
        });
    }

    public function testChecklistBlocksClusterScansUntilRegistryHostsAreConfigured(): void
    {
        $id = $this->connections->save('cluster', self::CONNECTION + ['namespace' => 'build', 'registries' => ' , ']);
        $row = $this->connections->get($id);
        $this->connections->update($row, $row['data'] + ['last_discovery' => ['status' => 'complete']]);
        $message = 'Add registry hostnames in the connection settings to scan cluster images.';
        self::assertSame($message, $this->connections->discoveryChecklist($id)[0]['scan_blocker']);

        $this->expectException(DomainException::class);
        $this->expectExceptionMessage($message);
        $this->connections->run($id, 'scan', afterDiscovery: true);
    }

    public function testOtherDiscoveryTypesRecordExistingInventoryAssets(): void
    {
        $this->withFixture(function (InventoryWorker $worker, Inventory $inventory, string $log): void {
            $directory = dirname($log);
            $repository = $directory.'/checkout';
            (new Process(['git', 'init', '--quiet', '--template=', $repository]))->mustRun();
            (new Process(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '--quiet', '--allow-empty', '-m', 'Fixture'], $repository))->mustRun();
            $filesystem = new Filesystem();
            $filesystem->dumpFile($directory.'/docker', <<<'SH'
#!/bin/sh
case "$1 $2" in
    'context show') printf '%s\n' 'fixture-default' ;;
    'container ls') ;;
    *) exit 1 ;;
esac
SH);
            $filesystem->dumpFile($directory.'/vault', <<<'SH'
#!/bin/sh
printf '%s' '{"private_key":"-----BEGIN OPENSSH PRIVATE KEY-----","known_hosts":"fixture public key"}'
SH);
            $filesystem->dumpFile($directory.'/bin/host-inventory', '# Fixture collector input');
            $filesystem->dumpFile($directory.'/ssh', <<<'SH'
#!/bin/sh
printf 'PATCHROCKET-HOST\t1\nhostname\tfixture-vm\nkernel\tfixture\nmanager\tAPT\nEND\n'
SH);
            chmod($directory.'/docker', 0700);
            chmod($directory.'/vault', 0700);
            chmod($directory.'/ssh', 0700);
            $reference = 'fixture.example/signed@sha256:'.str_repeat('1', 64);
            foreach ([
                'repository' => [['target' => $repository], 'repository', 'Repository registered.'],
                'registry' => [['target' => $reference], 'image', 'Registry image registered.'],
                'docker' => [[], 'docker', '0 containers discovered.'],
                'vm' => [['target' => 'fixture@vm.example', 'credential' => 'fixture:ssh'], 'linux', 'Host inventory collected.'],
            ] as $kind => [$input, $assetKind, $summary]) {
                $id = $this->connections->save($kind, ['name' => $kind] + $input);
                $this->connections->run($id, 'discover');
                $worker($this->queued);
                $discovery = $this->connections->discoveryChecklist($id)[0]['discovery'];
                self::assertSame('complete', $discovery['status']);
                self::assertSame($summary, $discovery['result']);
                self::assertSame($assetKind, $inventory->get($discovery['asset_id'])['kind']);
                $this->store->db->delete('assets', ['id' => $discovery['asset_id']]);
                self::assertArrayNotHasKey('asset_id', $this->connections->discoveryChecklist($id)[0]['discovery']);
            }
        });
    }

    public function testDiscoveryFailureSurvivesLaterWorkAndClearsAfterTargetChange(): void
    {
        $this->withFixture(function (InventoryWorker $worker, Inventory $inventory, string $log): void {
            $settings = ['name' => 'Source', 'target' => dirname($log).'/missing'];
            $id = $this->connections->save('repository', $settings);
            $this->connections->run($id, 'discover');
            self::assertTrue($this->connections->hasActiveInventoryWork('Source', operation: 'discover'));
            self::assertNull($this->connections->discoveryNeedingAttention(time()));
            self::assertSame(['id' => $id, 'state' => 'overdue'], $this->connections->discoveryNeedingAttention(time() + 7200));
            $worker($this->queued);
            $current = $this->connections->get($id)['data'];
            $failed = ['status' => 'failed', 'finished_at' => $current['finished_at'], 'result' => 'Repository path does not exist.'];
            self::assertSame($failed, $current['last_discovery']);
            self::assertSame(['id' => $id, 'state' => 'failed'], $this->connections->discoveryNeedingAttention(time()));

            $this->connections->save('repository', array_replace($settings, ['id' => $id, 'name' => 'Renamed', 'interval' => 60]));
            $this->connections->run($id, 'scan');
            self::assertTrue($this->connections->hasActiveInventoryWork('Renamed'));
            self::assertFalse($this->connections->hasActiveInventoryWork('Renamed', operation: 'discover'));
            self::assertNull($this->connections->discoveryNeedingAttention(time()));
            $worker($this->queued);
            self::assertSame($failed, $this->connections->discoveryChecklist($id)[0]['discovery']);
            self::assertSame(['id' => $id, 'state' => 'failed'], $this->connections->discoveryNeedingAttention(time()));
            self::assertSame([$id], array_column($this->connections->discoveryChecklist('', result: 'failed'), 'id'));
            self::assertSame([], $this->connections->discoveryChecklist('', result: 'complete'));

            $this->connections->save('repository', array_replace($settings, ['id' => $id, 'target' => dirname($log).'/other']));
            self::assertNull($this->connections->discoveryChecklist($id)[0]['discovery']);
            self::assertNull($this->connections->discoveryNeedingAttention(time()));
            self::assertSame([$id], array_column($this->connections->discoveryChecklist('', result: 'unrecorded'), 'id'));
        });
    }

    public function testLegacyDiscoveryTimestampFitsTheCurrentNamespaceScope(): void
    {
        $id = $this->connections->save('cluster', self::CONNECTION + ['namespace' => 'build', 'registries' => 'old.example']);
        $row = $this->connections->get($id);
        $finishedAt = '2026-11-20T10:00:00+00:00';
        $this->connections->update($row, $row['data'] + ['last_discovery_at' => $finishedAt, 'operation' => 'scan', 'status' => 'complete']);
        $legacy = ['status' => 'complete', 'finished_at' => $finishedAt];
        self::assertSame($legacy, $this->connections->discoveryChecklist($id)[0]['discovery']);
        self::assertSame([$id], array_column($this->connections->discoveryChecklist('', result: 'complete'), 'id'));

        $settings = ['id' => $id, 'name' => 'West', 'namespace_mode' => 'selected'];
        $this->connections->save('cluster', $settings + ['namespaces' => ['build'], 'registries' => 'new.example', 'platform' => 'linux/arm64']);
        self::assertSame($legacy, $this->connections->discoveryChecklist($id)[0]['discovery']);

        $this->connections->save('cluster', $settings + ['namespaces' => ['payments']]);
        self::assertNull($this->connections->discoveryChecklist($id)[0]['discovery']);
        self::assertArrayNotHasKey('last_discovery_at', $this->connections->get($id)['data']);
    }

    public function testWorkerRecordsTheFailureReasonForTheScan(): void
    {
        $this->withFixture(function (InventoryWorker $worker): void {
            $id = $this->connections->save('cluster', self::CONNECTION + [
                'namespace' => 'build', 'registries' => 'fixture.example', 'interval' => 60, 'host_asset' => 'missing-host',
            ]);
            $this->connections->run($id, 'scan');
            $worker($this->queued);
            $record = $this->connections->get($id)['data'];
            self::assertSame('The linked VM must exist in inventory.', $record['last_scan']['failure_reason']);
            self::assertSame($record['result'], $record['last_scan']['failure_reason']);
            self::assertSame($record['finished_at'], $record['last_scan']['finished_at']);
            self::assertSame('failed', $record['last_scan']['status']);
        });
    }

    public function testFailedClusterImageBatchCanRetryWithoutRescanningSuccessfulImages(): void
    {
        $this->withFixture(function (InventoryWorker $worker, Inventory $inventory, string $log): void {
            $id = $this->connections->save('cluster', self::CONNECTION + [
                'namespace' => 'build', 'registries' => 'fixture.example', 'interval' => 60,
            ]);
            $directory = dirname($log);
            $images = [
                'a-failing' => 'fixture.example/a-failing@sha256:'.str_repeat('1', 64),
                'z-working' => 'fixture.example/z-working@sha256:'.str_repeat('2', 64),
            ];
            $statuses = [];
            foreach ($images as $name => $reference) {
                $statuses[] = ['name' => $name, 'image' => $reference, 'imageID' => $reference, 'state' => ['running' => []]];
            }
            file_put_contents($directory.'/pods.json', Store::json(['items' => [[
                'metadata' => ['uid' => 'scan-pod', 'name' => 'scan-pod'],
                'status' => ['containerStatuses' => $statuses],
            ]]]));
            touch($directory.'/fail-image');

            $this->connections->run($id, 'scan');
            $worker($this->queued);
            $record = $this->connections->get($id)['data'];
            self::assertSame('failed', $record['status']);
            $reason = '1 workload discovered. 1 of 2 image scans failed. Check registry access and scanner availability, then retry.';
            self::assertSame($reason, $record['last_scan']['failure_reason']);
            $schedule = $this->connections->scheduledScans(time(), true)['rows'][0];
            self::assertSame('failed', $schedule['outcome']);
            self::assertSame($reason, $schedule['failure_reason']);
            self::assertSame('scheduled', $schedule['state']);
            $failedImage = hash('sha256', 'image/'.$images['a-failing']);
            $successfulImage = hash('sha256', 'image/'.$images['z-working']);
            self::assertTrue($schedule['has_failed_images']);
            self::assertFalse($this->connections->scheduledScans(time())['rows'][0]['has_failed_images']);
            self::assertTrue($this->connections->inventoryJobs(time(), '', '', '', $id, 1, true)['rows'][0]['has_failed_images']);
            self::assertFalse($this->connections->inventoryJobs(time(), '', '', '', $id, 1, false)['rows'][0]['has_failed_images']);
            self::assertTrue($this->connections->discoveryChecklist($id)[0]['scan']['has_failed_images']);
            self::assertSame(['name' => 'West', 'images' => [$failedImage]], $this->connections->failedScanImages($id));
            self::assertSame('failed', $inventory->get($failedImage)['data']['scan_outcome']);
            self::assertSame('complete', $inventory->get($successfulImage)['data']['scan_outcome']);

            unlink($directory.'/fail-image');
            $this->connections->run($id, 'scan');
            $worker($this->queued);
            self::assertSame([$images['a-failing'], $images['z-working'], $images['a-failing']],
                file($directory.'/image-scans', FILE_IGNORE_NEW_LINES));
            self::assertSame('complete', $inventory->get($failedImage)['data']['scan_outcome']);
            $schedule = $this->connections->scheduledScans(time(), true)['rows'][0];
            self::assertSame('complete', $schedule['outcome']);
            self::assertNull($schedule['failure_reason']);
            self::assertFalse($schedule['has_failed_images']);
            self::assertFalse($this->connections->inventoryJobs(time(), '', '', '', $id, 1, true)['rows'][0]['has_failed_images']);
            self::assertSame([], $this->connections->failedScanImages($id)['images']);
            self::assertSame('1 workload discovered. 1 image scan completed.', $this->connections->get($id)['data']['result']);
        });
    }

    public function testDeliveryDiscoveryAggregatesSelectedNamespacesAndReadsConfiguredArgoSeparately(): void
    {
        $this->withFixture(function (InventoryWorker $worker, Inventory $inventory, string $log, DeliveryDiscovery $delivery): void {
            $id = $this->connections->save('cluster', self::CONNECTION + ['namespaces' => ['build', 'payments']]);
            $this->connections->saveArgo($id, 'argocd', 'fixture:argo');
            $this->connections->run($id, 'delivery');
            $worker($this->queued);

            $data = $this->connections->get($id)['data'];
            self::assertSame('complete', $data['status']);
            self::assertSame('3 discovery candidate(s). Unavailable resource lists in payments: deployments.', $data['result']);
            self::assertEqualsCanonicalizing(['build', 'payments', 'argocd'], array_column($delivery->all(), 'namespace'));
            self::assertSame([
                'build services', 'build ingresses.networking.k8s.io', 'build deployments', 'build applications.argoproj.io',
                'payments services', 'payments ingresses.networking.k8s.io', 'payments deployments', 'payments applications.argoproj.io',
                'argocd applications.argoproj.io',
            ], file($log, FILE_IGNORE_NEW_LINES));
        });
    }

    private function withFixture(callable $test): void
    {
        $directory = sys_get_temp_dir().'/patchrocket-kube-scope-'.bin2hex(random_bytes(8));
        $filesystem = new Filesystem();
        $processPath = getenv('PATH');
        $envPath = $_ENV['PATH'] ?? null;
        try {
            $filesystem->dumpFile($directory.'/vault', <<<'SH'
#!/bin/sh
printf '%s' '{"kubeconfig":"{\"kind\":\"Config\",\"contexts\":[{\"name\":\"west\"}]}"}'
SH);
            $filesystem->dumpFile($directory.'/kubectl', <<<'SH'
#!/bin/sh
set -eu
scope=cluster
for arg; do
    case "$arg" in
        --namespace=*) scope="${arg#--namespace=}" ;;
        --all-namespaces) scope=all ;;
    esac
    if [ "${previous:-}" = get ]; then resource="$arg"; fi
    previous="$arg"
done
printf '%s %s\n' "$scope" "$resource" >> "$(dirname "$0")/queries"
case "$scope:$resource" in
    cluster:namespaces) printf '%s' '{"items":[{"metadata":{"name":"build"}},{"metadata":{"name":"payments"}},{"metadata":{"name":"tools"}}]}' ;;
    all:deployment,statefulset,daemonset)
        printf '%s' '{"items":[{"kind":"Deployment","metadata":{"uid":"build","name":"build","namespace":"build"}},{"kind":"Deployment","metadata":{"uid":"payments","name":"payments","namespace":"payments"}},{"kind":"Deployment","metadata":{"uid":"tools","name":"tools","namespace":"tools"}}]}' ;;
    *:deployment,statefulset,daemonset)
        printf '{"items":[{"kind":"Deployment","metadata":{"uid":"%s","name":"%s","namespace":"%s"}}]}' "$scope" "$scope" "$scope" ;;
    build:pods)
        if [ -f "$(dirname "$0")/pods.json" ]; then cat "$(dirname "$0")/pods.json"; else printf '%s' '{"items":[]}'; fi ;;
    *:services)
        printf '{"items":[{"metadata":{"name":"jenkins","namespace":"%s"}}]}' "$scope" ;;
    payments:deployments) exit 1 ;;
    argocd:applications.argoproj.io)
        printf '%s' '{"items":[{"metadata":{"name":"app","namespace":"argocd"}}]}' ;;
    *) printf '%s' '{"items":[]}' ;;
esac
SH);
            $filesystem->dumpFile($directory.'/trivy', <<<'SH'
#!/bin/sh
set -eu
if [ "$1" = convert ]; then
    printf '%s' '{"bomFormat":"CycloneDX","components":[]}'
    exit 0
fi
for subject; do :; done
directory=$(dirname "$0")
printf '%s\n' "$subject" >> "$directory/image-scans"
case "$subject" in
    fixture.example/a-failing@*) if [ -f "$directory/fail-image" ]; then exit 1; fi ;;
esac
printf '%s' '{"SchemaVersion":2,"Results":[]}'
SH);
            chmod($directory.'/vault', 0700);
            chmod($directory.'/kubectl', 0700);
            chmod($directory.'/trivy', 0700);
            $_ENV['PATH'] = $directory.':'.$processPath;
            putenv('PATH='.$_ENV['PATH']);
            $inventory = new Inventory($this->store);
            $repository = new Repository($inventory);
            $managers = new SecretManagers($this->store, new AnsibleVault($repository));
            $managers->save('fixture', 'vault', 'kv');
            $credentials = new ConnectionCredentials($managers, $repository);
            $hosts = new HostCollector($inventory, $directory);
            $infrastructure = new Infrastructure($inventory, $this->store);
            $delivery = new DeliveryDiscovery($this->store, $this->connections, new JenkinsConnections($this->store), new OperatorSettings($this->store));
            $worker = new InventoryWorker($this->connections, $hosts, $infrastructure, $repository,
                new AssetScans($inventory, $repository, $infrastructure, new Scanner($inventory, $this->store, $directory.'/trivy'), $this->store),
                $credentials, $inventory, new ManagedGit($managers, $directory), new DeploymentProvenance($this->store, $inventory, $repository),
                new ConnectionDeliveryDiscovery($hosts, $infrastructure, $credentials, $delivery),
                new \App\Discovery\KubernetesConnectionProbe($credentials, $managers, $repository));
            $test($worker, $inventory, $directory.'/queries', $delivery);
        } finally {
            if (null === $envPath) {
                unset($_ENV['PATH']);
            } else {
                $_ENV['PATH'] = $envPath;
            }
            putenv(false === $processPath ? 'PATH' : 'PATH='.$processPath);
            $filesystem->remove($directory);
        }
    }
}
