<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardReturnPath;
use App\Controller\DashboardListContext;
use App\Controller\DashboardReadApi;
use App\Fleet\Analysis;
use App\Remediation\ApprovalPolicy;
use App\Remediation\DashboardStatuses;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Messenger\MessageBus;

final class DashboardReadApiTest extends TestCase
{
    private Store $store;
    private Inventory $inventory;
    private DashboardReadApi $api;
    private Connections $connections;

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $this->inventory = new Inventory($this->store);
        $this->connections = new Connections($this->store, new MessageBus());
        $statuses = new DashboardStatuses($this->store, new ApprovalPolicy($this->store, $this->inventory));
        $this->api = new DashboardReadApi($this->store, new Analysis($this->store), $statuses, $this->connections);
    }

    public function testAssetInventoryFindsRunningContainersForAnImageAndItsDigestAliases(): void
    {
        $digest = 'sha256:'.str_repeat('a', 64);
        $image = $this->inventory->asset('image', 'runtime', 'Scanned image', ['digest' => $digest, 'origin' => 'registry']);
        $alias = $this->inventory->asset('image', 'alias', 'Observed image', ['digest' => $digest]);
        $other = $this->inventory->asset('image', 'other', 'Other image', ['digest' => 'sha256:'.str_repeat('b', 64)]);
        $legacy = $this->inventory->asset('image', 'legacy', 'Legacy image');
        $container = $this->inventory->asset('container', 'direct', 'Direct', ['running' => true]);
        $remote = $this->inventory->asset('container', 'remote', 'Remote', ['running' => true]);
        $stopped = $this->inventory->asset('container', 'stopped', 'Stopped', ['running' => false]);
        $unrelated = $this->inventory->asset('container', 'unrelated', 'Unrelated', ['running' => true]);
        $this->inventory->link($container, 'RUNS', $image, 'Fixture');
        $this->inventory->link($container, 'RUNS', $alias, 'Fixture');
        $this->inventory->link($remote, 'RUNS', $alias, 'Fixture');
        $this->inventory->link($stopped, 'RUNS', $alias, 'Fixture');
        $this->inventory->link($unrelated, 'RUNS', $other, 'Fixture');
        $this->inventory->link($unrelated, 'RUNS', $legacy, 'Fixture');
        $retired = $this->inventory->asset('image', 'retired', 'Retired image', ['origin' => 'registry']);
        $this->inventory->link($stopped, 'RUNS', $retired, 'Fixture');
        $registryOnly = $this->inventory->asset('image', 'registry-only', 'Registry-only image', ['origin' => 'registry']);
        $this->inventory->findings($image, 'Fixture', [[
            'advisory' => 'PP-RUNTIME-FIXTURE', 'package' => 'fixture/runtime', 'target' => 'composer.lock',
        ]]);
        $finding = $this->store->db->fetchOne('SELECT id FROM findings WHERE asset_id = ?', [$image]);
        $from = '/findings/'.$finding.'?from=%2Ffindings%3Fadvisory%3DPP-RUNTIME-FIXTURE#finding-runtime';
        $assets = function (array $query): array {
            $response = $this->api->assets(Request::create('/api/assets', 'GET', $query));

            return json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        };
        $results = $assets(['running_image' => $image, 'from' => $from]);
        self::assertSame(['id' => $image, 'name' => 'Scanned image', 'digest' => $digest, 'return' => $from], $results['runtimeScope']);
        self::assertSame([$container, $remote], array_column($results['assets'], 'id'));
        self::assertSame(['observed' => 3, 'running' => 2], $this->inventory->imageRuntime($this->inventory->get($image)));
        self::assertEqualsCanonicalizing([$image, $alias, $other, $legacy],
            $this->store->db->fetchFirstColumn($this->inventory->runtimeFindingAssetIds(true)));
        self::assertSame([$registryOnly], $this->store->db->fetchFirstColumn($this->inventory->runtimeFindingAssetIds(false)));
        self::assertSame([$remote], array_column($assets(['running_image' => $image, 'q' => 'REMOTE'])['assets'], 'id'));
        self::assertNull($assets(['running_image' => $other, 'from' => $from])['runtimeScope']['return']);
        self::assertNull($assets(['running_image' => $image, 'from' => '//external.invalid'.$from])['runtimeScope']['return']);
        self::assertSame([$unrelated], array_column($assets(['running_image' => $legacy])['assets'], 'id'));
        $missing = $assets(['running_image' => str_repeat('0', 64)]);
        self::assertNull($missing['runtimeScope']['name']);
        self::assertSame([], $missing['assets']);
        self::assertSame(400, $this->api->assets(Request::create('/api/assets?running_image=invalid'))->getStatusCode());
    }

    public function testAssetSearchPagesAndReturnsDisplayFieldsWithoutSbom(): void
    {
        for ($i = 0; $i <= 50; ++$i) {
            $name = sprintf('Scan_%%-%02d', $i);
            $id = $this->inventory->asset('image', $name, $name, [
                'scan_source' => 'Fixture',
                'sbom' => ['components' => [['purl' => 'pkg:generic/example']]],
            ]);
            $this->store->db->update('assets', ['observed_at' => sprintf('2026-11-20T10:%02d:00+00:00', $i)], ['id' => $id]);
        }
        $this->inventory->asset('image', 'other', 'Scan-other');
        $this->inventory->asset('repository', 'repo', 'Scan_% repository');

        $request = Request::create('/api/assets?kind=image&q=scan_%25');
        $first = json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertCount(50, $first['assets']);
        self::assertSame(['image', 'repository'], $first['kinds']);
        self::assertTrue($first['next']);
        self::assertSame('Scan_%-00', $first['assets'][0]['name']);
        self::assertSame('Fixture', $first['assets'][0]['scan_source']);
        self::assertArrayNotHasKey('data', $first['assets'][0]);

        $request->query->set('page', '2');
        $second = json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertFalse($second['next']);
        self::assertSame(['Scan_%-50'], array_column($second['assets'], 'name'));

        $request->query->set('sort', 'newest');
        $newest = json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('newest', $newest['sort']);
        self::assertSame(['Scan_%-00'], array_column($newest['assets'], 'name'));
        $request->query->set('sort', 'oldest');
        $oldest = json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('oldest', $oldest['sort']);
        self::assertSame(['Scan_%-50'], array_column($oldest['assets'], 'name'));
    }

    public function testAssetScanScopeDeduplicatesDescendantsAndUsesRecordedEvidence(): void
    {
        $parent = $this->inventory->asset('workload', 'parent', 'Fixture scope');
        $first = $this->inventory->asset('container', 'first', 'First container');
        $second = $this->inventory->asset('container', 'second', 'Second container');
        $image = $this->inventory->asset('image', 'shared', 'Fixture shared image');
        $outside = $this->inventory->asset('image', 'outside', 'Fixture outside image', ['scan_source' => 'Fixture']);
        foreach ([$first, $second] as $container) {
            $this->inventory->link($parent, 'HOSTS', $container, 'Fixture');
            $this->inventory->link($container, 'RUNS', $image, 'Fixture');
        }
        $this->inventory->link($image, 'HOSTS', $parent, 'Fixture');
        $this->inventory->link($parent, 'BUILT_FROM', $outside, 'Fixture');
        $this->inventory->findings($image, 'Legacy scan', [['advisory' => 'FIXTURE', 'package' => 'test/package', 'target' => 'composer.lock']]);
        $this->inventory->findings($image, 'Legacy scan', []);

        $from = '/assets/'.$parent.'#asset-vulnerabilities';
        $request = Request::create('/api/assets', 'GET', ['scope' => $parent, 'scan' => 'recorded', 'q' => 'Fixture', 'from' => $from]);
        $read = fn (): array => json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $result = $read();
        self::assertSame([$image], array_column($result['assets'], 'id'));
        self::assertSame(['id' => $parent, 'name' => 'Fixture scope', 'return' => $from], $result['assetScope']);

        $request->query->set('page', '2');
        $request->query->set('selected_result', $image);
        self::assertSame(1, $read()['selectedPage']);
        $request->query->set('selected_result', $outside);
        self::assertNull($read()['selectedPage']);
        $request->query->remove('page');
        $request->query->remove('selected_result');

        $request->query->set('from', '/assets/'.$outside.'#asset-vulnerabilities');
        self::assertNull($read()['assetScope']['return']);
        $request->query->set('scope', str_repeat('f', 64));
        self::assertSame([], $read()['assets']);
        $request->query->set('scope', 'invalid');
        self::assertSame(400, $this->api->assets($request)->getStatusCode());
    }

    public function testAssetScheduleFiltersAreIndependentOfLastScanOutcomes(): void
    {
        $now = time();
        $scan = ['scan_source' => 'Fixture scanner', 'scanned_at' => '2026-11-20T08:00:00+00:00'];
        $recorded = $this->inventory->asset('image', 'recorded-due', 'Recorded due asset', $scan);
        $failed = $this->inventory->asset('image', 'failed-due', 'Failed due asset', $scan + [
            'scan_outcome' => 'failed', 'scan_attempted_at' => '2026-11-20T09:00:00+00:00',
        ]);
        $running = $this->inventory->asset('image', 'running', 'Running scan asset');
        $scheduled = $this->inventory->asset('repository', 'future', 'Scheduled source');
        $unscheduled = $this->inventory->asset('image', 'unscheduled', 'Unscheduled image', $scan);
        foreach ([
            [$recorded, $now - 500, 0], [$failed, $now - 50, 0],
            [$running, $now - 500, $now + 600], [$scheduled, $now + 600, 0],
        ] as [$id, $next, $lease]) {
            $this->store->db->insert('scan_schedules', [
                'id' => $id, 'next_at' => $next, 'lease_until' => $lease, 'interval_seconds' => 3600, 'data' => '{}',
            ]);
        }
        $get = function (string $schedule, string $scan = '', array $options = []): array {
            $request = Request::create('/api/assets', 'GET', compact('schedule', 'scan') + $options);

            return json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        };

        $due = $get('due');
        self::assertSame('due', $due['schedule']);
        self::assertSame([$failed, $recorded], array_column($due['assets'], 'id'));
        self::assertSame(['failed', 'recorded'], array_column($due['assets'], 'scan_state'));
        self::assertSame([$now - 50, $now - 500], array_column($due['assets'], 'schedule_next_at'));
        $oldestFirst = $get('due', options: ['sort' => 'next-due', 'overview_from' => '/#overview-scan-assets-due']);
        self::assertSame([$recorded, $failed], array_column($oldestFirst['assets'], 'id'));
        self::assertSame([$recorded, $failed, $scheduled, $running, $unscheduled],
            array_column($get('', options: ['sort' => 'next-due'])['assets'], 'id'));
        self::assertSame('/#overview-scan-assets-due', $oldestFirst['overviewScanReturn']);
        self::assertNull($get('due', options: ['overview_from' => '//outside.example/#overview-scan-assets-due'])['overviewScanReturn']);
        self::assertSame([$recorded], array_column($get('due', 'recorded')['assets'], 'id'));
        self::assertSame([$running], array_column($get('running', 'unscanned')['assets'], 'id'));
        self::assertSame([$scheduled], array_column($get('scheduled')['assets'], 'id'));
        $withoutSchedule = $get('unscheduled', 'recorded')['assets'];
        self::assertSame([$unscheduled], array_column($withoutSchedule, 'id'));
        self::assertNull($withoutSchedule[0]['schedule_next_at']);
        self::assertSame('', $get('unrecognized')['schedule']);
    }

    public function testAssetSearchUsesRecordedIdentifiersAndKeepsNamesAndScopes(): void
    {
        $digest = 'sha256:'.str_repeat('a', 64);
        $image = $this->inventory->asset('image', 'web-amd64', 'web', [
            'digest' => $digest, 'platform' => 'linux/amd64', 'scan_source' => 'Fixture scanner',
            'sbom' => ['components' => [['name' => 'hidden-component']]],
        ]);
        $armImage = $this->inventory->asset('image', 'web-arm64', 'web', [
            'digest' => 'sha256:'.str_repeat('b', 64), 'platform' => 'linux/arm64',
        ]);
        $host = $this->inventory->asset('linux', 'edge-host', 'edge', [
            'ssh_alias' => 'ops@edge.example', 'hostname' => 'edge-prod-01',
        ]);
        $repository = $this->inventory->asset('repository', 'app-repo', 'app', [
            'subdirectory' => 'services/web_%', 'revision' => str_repeat('c', 40),
            'path' => '/worker/internal-checkout', 'source_url' => 'https://git.example.test/app.git',
        ]);
        $this->inventory->asset('repository', 'other-repo', 'other app', ['subdirectory' => 'services/web-x']);
        $this->inventory->asset('container', 'web-1', 'web', ['scope' => 'cluster-west/prod']);

        $search = function (string $value, array $filters = []): array {
            $request = Request::create('/api/assets', 'GET', ['q' => $value] + $filters);

            return json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR)['assets'];
        };
        $names = $search('web', ['kind' => 'image']);
        self::assertEqualsCanonicalizing([$image, $armImage], array_column($names, 'id'));
        self::assertSame([$armImage], array_column($search('web', ['asset_id' => strtoupper($armImage)]), 'id'));
        self::assertSame([], $search('web', ['asset_id' => $armImage, 'kind' => 'repository']));
        $match = $search(strtoupper($digest), ['kind' => 'image', 'scan' => 'recorded']);
        self::assertSame([$image], array_column($match, 'id'));
        self::assertSame([
            ['label' => 'Image digest', 'value' => $digest],
            ['label' => 'Platform', 'value' => 'linux/amd64'],
        ], $match[0]['identifiers']);
        self::assertSame([$armImage], array_column($search(strtoupper($armImage)), 'id'));
        self::assertSame([$host], array_column($search('edge-prod'), 'id'));
        self::assertSame([$host], array_column($search('ops@edge.example'), 'id'));
        self::assertSame([$repository], array_column($search('  SERVICES/web_%  '), 'id'));
        self::assertSame([$repository], array_column($search(str_repeat('c', 40)), 'id'));
        self::assertSame(['web'], array_column($search('cluster-west/prod'), 'name'));
        self::assertSame([], $search('hidden-component'));
        self::assertSame([], $search('/worker/internal-checkout'));
        self::assertSame([], $search('git.example.test'));
    }

    public function testImageSearchFindsRegistryDigestsOnRecordedImages(): void
    {
        $localDigest = 'sha256:'.str_repeat('a', 64);
        $manifestDigest = 'sha256:'.str_repeat('b', 64);
        $reference = 'registry.example.test/team/app@'.$manifestDigest;
        $local = $this->inventory->asset('image', 'local-image', 'app:stable', [
            'digest' => $localDigest, 'repo_digests' => [$reference, $reference],
            'scan_source' => 'Fixture scanner',
        ]);
        $registered = $this->inventory->asset('image', 'registered-image', $reference, ['digest' => $reference]);
        $this->inventory->asset('image', 'legacy-scalar', 'Unrelated legacy image', ['repo_digests' => $reference]);
        $this->inventory->asset('image', 'legacy-object', 'Unrelated nested data', ['repo_digests' => [['ref' => $reference]]]);
        $this->inventory->asset('repository', 'other-kind', 'Unrelated repository', ['repo_digests' => [$reference]]);

        $search = function (string $value, string $scan = ''): array {
            $request = Request::create('/api/assets', 'GET', ['q' => $value, 'scan' => $scan]);

            return json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR)['assets'];
        };
        $matched = $search('docker-pullable://'.$reference, 'recorded');
        self::assertSame([$local], array_column($matched, 'id'));
        self::assertSame([
            ['label' => 'Image digest', 'value' => $localDigest],
            ['label' => 'Registry digest', 'value' => $reference],
        ], $matched[0]['identifiers']);
        self::assertArrayNotHasKey('matched_registry_digest', $matched[0]);
        self::assertEqualsCanonicalizing([$local, $registered], array_column($search(strtoupper($manifestDigest)), 'id'));
        self::assertSame([$local], array_column($search('containerd://'.$localDigest), 'id'));
    }

    public function testListContextKeepsFiltersForTheExpectedListOnly(): void
    {
        $request = Request::create('/detail', 'GET', ['from' => '/app/assets?kind=image&q=portal%20worker&page=2']);
        self::assertSame(['from' => '/app/assets?kind=image&q=portal%20worker&page=2'],
            DashboardListContext::parameters($request, DashboardListContext::ASSETS));
        self::assertSame([], DashboardListContext::parameters($request, DashboardListContext::REMEDIATIONS));
        self::assertSame(['from' => '/app/assets?kind=image&q=portal%20worker&page=2'], DashboardListContext::asset($request));

        $findings = '/findings?view=assets&advisory=PP-FIXTURE#vulnerability-results';
        $request->query->set('from', $findings);
        self::assertSame(['from' => $findings], DashboardListContext::asset($request));

        $fleet = '/app/fleet?impact_q=test&package_q=shared#shared-dependencies/package%3Apkg%3Acomposer%2Ftest%2Fexample/'.str_repeat('c', 64);
        $request->query->set('from', $fleet);
        self::assertSame(['from' => $fleet], DashboardListContext::asset($request));
        $request->query->set('from', '//elsewhere.example'.$fleet);
        self::assertSame([], DashboardListContext::asset($request));

        $findingId = str_repeat('f', 64);
        $finding = '/findings/'.$findingId.'?'.http_build_query(['from' => $findings]).'#finding-details';
        $request->query->set('from', $finding);
        self::assertSame($findingId, DashboardListContext::findingDetailId($finding));
        self::assertSame(['from' => $finding], DashboardListContext::asset($request));
        foreach (['//elsewhere.example'.$finding, str_replace('#finding-details', '#prepare-patch', $finding)] as $invalidFinding) {
            $request->query->set('from', $invalidFinding);
            self::assertSame([], DashboardListContext::asset($request));
        }

        foreach (['build-source', 'deployment-source', 'related-source'] as $section) {
            $source = str_replace('#finding-details', '#'.$section, $finding);
            foreach ([$source, $source.'/'.str_repeat('a', 64)] as $origin) {
                $request->query->set('from', $origin);
                self::assertSame(['from' => $origin], DashboardListContext::asset($request));
                self::assertSame('related-source' === $section ? ['from' => $origin] : [], DashboardListContext::finding($request));
                self::assertNull(DashboardListContext::findingDetailId($origin));
            }
        }
        $relatedSource = str_replace('#finding-details', '#related-source', $finding);
        foreach (['//elsewhere.example'.$relatedSource, str_replace($findingId, 'invalid', $relatedSource),
            $relatedSource.'-other', $relatedSource.'/bad-id', $relatedSource.'/'.str_repeat('a', 64).'/extra'] as $invalidSource) {
            $request->query->set('from', $invalidSource);
            self::assertSame([], DashboardListContext::asset($request));
            self::assertSame([], DashboardListContext::finding($request));
        }

        $queue = '/app/queue?inventory_state=failed#scheduled-scans';
        $request->query->set('from', $queue);
        self::assertSame(['from' => $queue], DashboardListContext::asset($request));
        self::assertSame(['url' => $queue, 'kind' => 'queue', 'label' => 'Queue'], DashboardListContext::connectionSettings($queue));
        self::assertNull(DashboardReturnPath::queueSection($queue, 'inventory-jobs'));
        foreach ([['asset', 64], ['connection', 32], ['connection', 64]] as [$kind, $length]) {
            $selectedScan = $queue.'/'.$kind.'/'.str_repeat('c', $length);
            self::assertSame($selectedScan, DashboardReturnPath::queueSection($selectedScan, 'scheduled-scans'));
            $request->query->set('from', $selectedScan);
            self::assertSame(['from' => $selectedScan], DashboardListContext::asset($request));
        }
        self::assertNull(DashboardReturnPath::queueSection($queue.'/asset/'.str_repeat('c', 32), 'scheduled-scans'));
        self::assertNull(DashboardReturnPath::queueSection($queue.'/other/'.str_repeat('c', 64), 'scheduled-scans'));
        $inventoryJobs = '/app/queue?inventory_state=overdue#inventory-jobs';
        self::assertSame($inventoryJobs, DashboardReturnPath::queueSection($inventoryJobs, 'inventory-jobs'));
        foreach ([32, 64] as $length) {
            $inventoryJob = $inventoryJobs.'/'.str_repeat('a', $length);
            self::assertSame($inventoryJob, DashboardReturnPath::queueSection($inventoryJob, 'inventory-jobs'));
        }
        self::assertNull(DashboardReturnPath::queueSection($inventoryJobs.'/invalid', 'inventory-jobs'));
        self::assertNull(DashboardReturnPath::queueSection('//external.example'.$inventoryJobs, 'inventory-jobs'));
        $clusterDirectory = '/app/clusters?q=Cluster&page=2#connection-result-'.str_repeat('a', 32);
        $repositoryDirectory = '/app/repositories?q=Repository&page=2#connection-result-'.str_repeat('b', 64);
        self::assertSame(['url' => $clusterDirectory, 'label' => 'Kubernetes connections'], DashboardListContext::inventoryDirectory($clusterDirectory));
        self::assertSame(['url' => $repositoryDirectory, 'label' => 'Source repositories'], DashboardListContext::inventoryDirectory($repositoryDirectory));
        self::assertSame($clusterDirectory, DashboardListContext::kubernetesDirectory($clusterDirectory));
        self::assertNull(DashboardListContext::kubernetesDirectory($repositoryDirectory));
        foreach (['//external.example'.$clusterDirectory, $clusterDirectory.'-extra', str_replace('/app/clusters', '/app/assets', $clusterDirectory)] as $invalidDirectory) {
            self::assertNull(DashboardListContext::inventoryDirectory($invalidDirectory));
        }
        $workerOrigins = [
            $inventoryJobs.'/'.str_repeat('a', 32) => 'Return to inventory job',
            $queue.'/asset/'.str_repeat('b', 64) => 'Return to scheduled scan',
            '/app/queue?job_state=queued#remediation-jobs/prepare/'.str_repeat('c', 24) => 'Return to remediation job',
            '/app/queue?check_state=queued#connection-checks/'.str_repeat('d', 32) => 'Return to connection check',
            '/app/queue?vm_state=worker#vm-package-jobs/'.str_repeat('e', 64) => 'Return to VM package update',
            '/app/queue?inventory_state=failed#transports/kubernetes_checks' => 'Return to queue',
        ];
        foreach ($workerOrigins as $origin => $label) {
            self::assertSame(['url' => $origin, 'label' => $label], DashboardListContext::workerQueueReturn($origin));
            self::assertNull(DashboardListContext::workerQueueReturn('//external.example'.$origin));
        }
        self::assertNull(DashboardListContext::workerQueueReturn('/app/queue#workers'));
        self::assertNull(DashboardListContext::workerQueueReturn('/app/queue#transports/jobs/extra'));
        self::assertNull(DashboardListContext::workerQueueReturn($inventoryJobs.'/invalid'));
        foreach (['getting-started-inventory-worker', 'getting-started-checks-worker'] as $check) {
            $origin = '/settings/getting-started?discovery_job=queued#'.$check;
            self::assertSame(['url' => $origin, 'label' => 'Return to installation checks'], DashboardListContext::workerQueueReturn($origin, true));
            self::assertNull(DashboardListContext::workerQueueReturn($origin));
            self::assertNull(DashboardListContext::workerQueueReturn($origin.'/extra', true));
            self::assertNull(DashboardListContext::workerQueueReturn('//external.example'.$origin, true));
        }
        foreach (['jobs', 'kubernetes_checks'] as $transport) {
            $workers = '/app/queue?inventory_state=queued&worker_transport='.$transport.'#workers';
            self::assertSame(['url' => $workers, 'transport' => $transport], DashboardListContext::workerSetupQueue($workers));
        }
        foreach (['//external.example'.$workers, '/app/queue#workers', '/app/queue?worker_transport=unknown#workers',
            '/app/queue?worker_transport%5B%5D=jobs#workers', '/app/queue?worker_transport=jobs#workers/extra'] as $invalid) {
            self::assertNull(DashboardListContext::workerSetupQueue($invalid));
        }

        $releaseTrackers = '/app/queue?release_state=due#release-trackers';
        $releaseTracker = $releaseTrackers.'/'.str_repeat('a', 24);
        $request->query->set('from', $releaseTracker);
        self::assertSame(['from' => $releaseTracker], DashboardListContext::remediation($request));
        $request->query->set('from', $releaseTrackers.'/invalid');
        self::assertSame(['from' => $releaseTrackers], DashboardListContext::remediation($request));

        $jobs = '/app/queue?scan_state=queued&job_state=failed#remediation-jobs';
        $prepare = $jobs.'/prepare/'.str_repeat('a', 24);
        $next = str_repeat('b', 24);
        $request->query->set('from', $prepare);
        self::assertSame(['from' => $prepare], DashboardListContext::remediation($request));
        self::assertSame(['from' => $jobs.'/prepare/'.$next],
            DashboardListContext::withPreparationJobAttempt(DashboardListContext::remediation($request), $next));
        $independent = $jobs.'/independent/'.str_repeat('a', 24);
        $request->query->set('from', $independent);
        self::assertSame(['from' => $independent],
            DashboardListContext::withPreparationJobAttempt(DashboardListContext::remediation($request), $next));
        $request->query->set('from', $jobs.'/prepare/invalid');
        self::assertSame(['from' => $jobs], DashboardListContext::remediation($request));

        $schedule = '/settings/policy?policy_q=service#rollout-schedule-'.str_repeat('a', 24);
        $request->query->set('from', $schedule);
        self::assertSame([], DashboardListContext::remediation($request));
        $request->attributes->set('_dashboard_role', 'admin');
        self::assertSame(['from' => $schedule], DashboardListContext::remediation($request));
        foreach (['//elsewhere.example'.$schedule, $schedule.'-extra', str_replace('/settings/policy', '/settings/scanning', $schedule)] as $invalid) {
            $request->query->set('from', $invalid);
            self::assertSame([], DashboardListContext::remediation($request));
        }
        $request->attributes->remove('_dashboard_role');

        $scanAsset = str_repeat('b', 64);
        $scanEditor = '/settings/scanning?asset='.$scanAsset.'&asset_q=checkout#recurring-scans';
        self::assertSame(['url' => $scanEditor, 'id' => $scanAsset], DashboardListContext::scanSettingsSelection($scanEditor));
        foreach (['//external.example'.$scanEditor, str_replace('asset=', 'asset[]=', $scanEditor),
            str_replace($scanAsset, 'invalid', $scanEditor), str_replace('#recurring-scans', '#scanner-worker', $scanEditor)] as $invalid) {
            self::assertNull(DashboardListContext::scanSettingsSelection($invalid));
        }

        $publication = '/remediations/'.str_repeat('a', 24).'?publish_base=release%2Fstable#pull-request';
        $request->query->set('from', $publication);
        self::assertSame(['url' => $publication, 'kind' => 'pull-request', 'label' => 'Pull request'], DashboardListContext::connectionSettings($publication));
        self::assertSame([], DashboardListContext::asset($request));
        self::assertNull(DashboardListContext::connectionSettings('//external.example'.$publication));
        self::assertNull(DashboardListContext::connectionSettings(str_replace('#pull-request', '#approval', $publication)));

        $rollout = '/remediations/'.str_repeat('a', 24).'?rollout_connection='.str_repeat('b', 32).'#runtime-verification';
        $request->query->set('from', $rollout);
        self::assertSame(['url' => $rollout, 'kind' => 'runtime-verification', 'label' => 'Runtime verification'],
            DashboardListContext::connectionSettings($rollout));
        self::assertSame([], DashboardListContext::asset($request));
        self::assertNull(DashboardListContext::connectionSettings('/remediations#runtime-verification'));
        $event = '/remediations/'.str_repeat('a', 24).'?events=failed&event_q=cluster#execution-event-'
            .str_repeat('0', 20).'-'.str_repeat('b', 12);
        self::assertSame(['url' => $event, 'kind' => 'runtime-verification', 'label' => 'Rollout evidence'],
            DashboardListContext::connectionSettings($event));
        self::assertNull(DashboardListContext::connectionSettings($event.'/unexpected'));

        $checklist = '/settings/getting-started?connection=repository#getting-started-discovery';
        $request->query->set('from', $checklist);
        self::assertSame(['from' => $checklist], DashboardListContext::asset($request));
        self::assertSame(['url' => $checklist, 'kind' => 'getting-started', 'label' => 'Getting started'],
            DashboardListContext::connectionSettings($checklist));
        self::assertSame(DashboardListContext::connectionSettings($checklist), DashboardListContext::credentialSettings($checklist));
        foreach (['source', 'vm', 'docker', 'registry', 'cluster'] as $kind) {
            $choice = '/settings/getting-started#getting-started-connect-'.$kind;
            self::assertSame(['url' => $choice, 'kind' => 'getting-started', 'label' => 'Getting started'],
                DashboardListContext::connectionSettings($choice));
        }
        self::assertNull(DashboardListContext::connectionSettings('/settings/getting-started#getting-started-connect-other'));
        foreach (['sources', 'targets'] as $directory) {
            $choice = '/settings/getting-started?discovery_result=complete#getting-started-manage-'.$directory;
            self::assertSame(['url' => $choice, 'kind' => 'getting-started', 'label' => 'Getting started'],
                DashboardListContext::connectionSettings($choice));
            self::assertNull(DashboardListContext::connectionSettings('//external.example'.$choice));
            self::assertNull(DashboardListContext::connectionSettings($choice.'/extra'));
        }
        $checklistPolicy = '/settings/getting-started?discovery_q=fixture#getting-started-policy';
        self::assertSame(['url' => $checklistPolicy, 'label' => 'Return to Getting started'], DashboardListContext::policySettings($checklistPolicy));
        self::assertNull(DashboardListContext::policySettings($checklist));
        self::assertNull(DashboardListContext::policySettings('//external.example'.$checklistPolicy));
        $editor = '/app/repositories?edit=new&from='.rawurlencode($checklist);
        self::assertSame(['url' => $editor, 'kind' => 'connection-editor', 'label' => 'Repository connection'],
            DashboardListContext::credentialSettings($editor));
        self::assertNotNull(DashboardListContext::credentialSettings('/settings/connections#connection-vm'));
        self::assertNotNull(DashboardListContext::credentialSettings('/settings/connections?edit='.str_repeat('a', 64).'#connection-vm'));
        self::assertNull(DashboardListContext::credentialSettings('/app/clusters?edit[]=new'));
        self::assertNull(DashboardListContext::credentialSettings('/app/repositories?edit=new#other'));
        self::assertNull(DashboardListContext::credentialSettings('//external.example'.$editor));

        $asset = '/assets/'.str_repeat('a', 64);
        $scanEvidence = $asset.'?from=%2Fassets%3Fscan%3Dfailed#scan-failure';
        self::assertSame($scanEvidence, DashboardListContext::assetDetail($scanEvidence));
        self::assertSame($asset.'#asset-title', DashboardListContext::assetDetail($asset.'#asset-title'));
        $scanSchedule = $asset.'?from=%2Fassets%3Fschedule%3Ddue#'.DashboardListContext::ASSET_SCAN_SCHEDULE_SECTION;
        self::assertSame($scanSchedule, DashboardListContext::assetDetail($scanSchedule));
        self::assertNull(DashboardListContext::assetDetail('//other.example'.$scanSchedule));
        $relatedAsset = $asset.'?relation_q=container&relation_page=2#'.DashboardListContext::ASSET_RELATION_PREFIX.str_repeat('b', 64);
        $request->query->set('from', $relatedAsset);
        self::assertSame(['from' => $relatedAsset], DashboardListContext::asset($request));
        foreach (['//other.example'.$relatedAsset, str_replace($asset, '/assets/invalid', $relatedAsset), $relatedAsset.'b'] as $invalidRelation) {
            $request->query->set('from', $invalidRelation);
            self::assertSame([], DashboardListContext::asset($request));
        }
        $vulnerabilities = $asset.'?from=%2Fassets%3Fkind%3Dimage#'.DashboardListContext::ASSET_VULNERABILITIES_SECTION;
        $vulnerabilitySection = [DashboardListContext::ASSET_VULNERABILITIES_SECTION];
        self::assertSame($vulnerabilities, DashboardListContext::assetDetail($vulnerabilities, $vulnerabilitySection));
        self::assertNull(DashboardListContext::assetDetail($vulnerabilities));
        self::assertNull(DashboardListContext::assetDetail($scanEvidence, $vulnerabilitySection));
        self::assertNull(DashboardListContext::assetDetail('//other.example'.$vulnerabilities, $vulnerabilitySection));
        foreach (['//other.example'.$asset, '/assets', '/assets/invalid', $asset.'#unrelated', ['from' => $asset]] as $invalid) {
            self::assertNull(DashboardListContext::assetDetail($invalid));
        }

        foreach (['//example.test/assets', '/assets/other', '/app/queue#other', '/settings/getting-started#other', ['from' => '/assets']] as $invalid) {
            $request->query->set('from', $invalid);
            self::assertSame([], DashboardListContext::parameters($request, DashboardListContext::ASSETS));
            self::assertSame([], DashboardListContext::asset($request));
            self::assertNull(DashboardListContext::connectionSettings($invalid));
        }
    }

    public function testFindingHistoryOnlyAcceptsAnInternalFindingAndFilters(): void
    {
        $id = str_repeat('f', 64);
        $finding = '/findings/'.$id;
        $list = '/findings?asset_name=App+worker&package=fixture%2Flibrary';
        $history = $finding.'?'.http_build_query(['from' => $list]).'#remediation-history';
        self::assertSame(['id' => $id, 'from' => $list], DashboardListContext::findingHistory($history));
        $request = Request::create('/remediations/detail', 'GET', ['from' => $history]);
        self::assertSame(['from' => $history], DashboardListContext::remediation($request));
        $untrustedList = $finding.'?'.http_build_query(['from' => '//elsewhere.example/findings']).'#remediation-history';
        self::assertSame(['id' => $id], DashboardListContext::findingHistory($untrustedList));

        $asset = '/assets/'.str_repeat('a', 64).'?from=%2Fassets%3Fkind%3Dimage#asset-finding-'.$id;
        $request->query->set('from', $asset);
        self::assertSame(['from' => $asset], DashboardListContext::finding($request));
        $assetHistory = $finding.'?'.http_build_query(['from' => $asset]).'#remediation-history';
        self::assertSame(['id' => $id, 'from' => $asset], DashboardListContext::findingHistory($assetHistory));
        $request->query->set('from', $assetHistory);
        self::assertSame(['from' => $assetHistory], DashboardListContext::remediation($request));

        $plan = '/remediations/'.str_repeat('a', 24).'?events=failed&event_q=checkout#remediation-original-finding';
        $request->query->set('from', $plan);
        self::assertSame(['from' => $plan], DashboardListContext::finding($request));
        $planHistory = $finding.'?'.http_build_query(['from' => $plan]).'#remediation-history';
        self::assertSame(['id' => $id, 'from' => $plan], DashboardListContext::findingHistory($planHistory));
        foreach (['//elsewhere.example'.$plan, str_replace(str_repeat('a', 24), 'invalid', $plan),
            str_replace('#remediation-original-finding', '#execution-timeline', $plan), $plan.'/extra'] as $invalidPlan) {
            $request->query->set('from', $invalidPlan);
            self::assertSame([], DashboardListContext::finding($request));
        }

        foreach (['//elsewhere.example'.$asset, str_replace('#asset-finding-'.$id, '#asset-title', $asset), '/assets/invalid#asset-finding-'.$id] as $invalidAsset) {
            $request->query->set('from', $invalidAsset);
            self::assertSame([], DashboardListContext::finding($request));
        }

        foreach (['//elsewhere.example'.$finding.'#remediation-history', '/findings/invalid#remediation-history', $finding, $finding.'#prepare-patch'] as $invalid) {
            $request->query->set('from', $invalid);
            self::assertNull(DashboardListContext::findingHistory($invalid));
            self::assertSame([], DashboardListContext::remediation($request));
        }
    }

    public function testConnectionFailureFilterPagesOnlyImagesInTheRecordedBatch(): void
    {
        $connection = $this->connections->save('cluster', ['name' => 'West', 'target' => 'west', 'credential' => 'fixture:kube']);
        $images = [];
        for ($index = 0; $index <= 50; ++$index) {
            $name = sprintf('Batch image %02d', $index);
            $images[] = $this->inventory->asset('image', $name, $name);
        }
        $this->inventory->asset('image', 'different', 'Other failed image', ['scan_outcome' => 'failed']);
        $row = $this->connections->get($connection);
        $this->connections->update($row, $row['data'] + ['last_scan' => ['status' => 'failed', 'failed_images' => $images]]);
        $queue = '/app/queue?inventory_state=failed#scheduled-scans';
        $request = Request::create('/api/assets', 'GET', ['failed_connection' => $connection, 'from' => $queue]);
        $request->attributes->set('_dashboard_role', 'viewer');
        self::assertSame(403, $this->api->assets($request)->getStatusCode());
        $request->attributes->set('_dashboard_role', 'admin');
        $read = fn (): array => json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $result = $read();
        self::assertSame(array_slice($images, 0, 50), array_column($result['assets'], 'id'));
        $batch = ['id' => $connection, 'name' => 'West', 'hasImages' => true, 'queueReturn' => $queue, 'checklistReturn' => null];
        self::assertSame($batch, $result['failedConnection']);
        self::assertTrue($result['next']);
        $request->query->set('page', '2');
        $second = $read();
        self::assertSame([$images[50]], array_column($second['assets'], 'id'));
        self::assertFalse($second['next']);
        $request->query->set('page', '1');
        $request->query->set('q', 'Other failed');
        self::assertSame([], $read()['assets']);
        $checklist = '/settings/getting-started?connection='.$connection.'&discovery_q=West#getting-started-discovery';
        $request->query->set('from', $checklist);
        self::assertSame(array_replace($batch, ['queueReturn' => null, 'checklistReturn' => $checklist]), $read()['failedConnection']);
        $request->query->set('from', '//example.invalid/settings/getting-started#getting-started-discovery');
        self::assertNull($read()['failedConnection']['checklistReturn']);

        $latest = $this->connections->get($connection);
        $this->connections->update($latest, array_replace($latest['data'], ['last_scan' => ['status' => 'complete']]));
        $request->query->remove('q');
        $result = $read();
        self::assertFalse($result['failedConnection']['hasImages']);
        self::assertSame([], $result['assets']);
    }

    public function testBroadenedAssetLookupReturnsOnlyToAnAuthorizedScope(): void
    {
        $id = $this->inventory->asset('image', 'outside-scope', 'Image from the wider inventory');
        $anchor = '#asset-result-'.$id;
        $batch = '/assets?failed_connection='.str_repeat('c', 32).'&sort=scan-failures'.$anchor;
        $runtime = '/app?running_image='.str_repeat('a', 64).'&q=worker'.$anchor;
        $scope = '/app/assets?scope='.str_repeat('b', 64).'&asset_id='.$id.$anchor;
        $read = function (mixed $from, string $role, array $filters = []) use ($id): array {
            $request = Request::create('/api/assets', 'GET', $filters + ['asset_id' => $id, 'from' => $from]);
            $request->attributes->set('_dashboard_role', $role);

            return json_decode($this->api->assets($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        };
        $lookup = $read($batch, 'admin');
        self::assertSame([$id], array_column($lookup['assets'], 'id'));
        self::assertSame(['url' => $batch, 'label' => 'Failed scan images'], $lookup['scopedInventoryReturn']);
        self::assertNull($read($batch, 'viewer')['scopedInventoryReturn']);
        self::assertSame(['url' => $runtime, 'label' => 'Running containers'], $read($runtime, 'viewer')['scopedInventoryReturn']);
        self::assertSame(['url' => $scope, 'label' => 'Scoped assets'], $read($scope, 'viewer')['scopedInventoryReturn']);
        self::assertNull($read($batch, 'admin', ['scope' => $id])['scopedInventoryReturn']);
        foreach (['//example.invalid'.$batch, '/findings?scope='.$id.$anchor, '/assets?asset_id='.$id.$anchor,
            '/assets?scope='.$id.'#asset-results', '/assets?scope%5B%5D='.$id.$anchor, ['return' => $scope]] as $invalid) {
            self::assertNull($read($invalid, 'admin')['scopedInventoryReturn']);
        }
    }

    public function testScanFilterUsesRecordedEvidenceAndDistinguishesTheLatestFailure(): void
    {
        $success = '2026-11-20T10:00:00+00:00';
        $failure = '2026-11-20T11:00:00+00:00';
        $this->inventory->asset('image', 'a', 'Fixture image failed', [
            'scan_source' => 'Test scan', 'scanned_at' => $success, 'scan_outcome' => 'failed', 'scan_attempted_at' => $failure,
        ]);
        $recovered = $this->inventory->asset('image', 'b', 'Fixture image recovered', [
            'scan_source' => 'Test scan', 'scanned_at' => $failure, 'scan_outcome' => 'failed', 'scan_attempted_at' => $success,
        ]);
        $this->store->db->insert('scan_schedules', [
            'id' => $recovered, 'next_at' => 0, 'lease_until' => 0, 'interval_seconds' => 3600,
            'data' => Store::json(['attempted_at' => $success, 'outcome' => 'failed']),
        ]);
        $this->inventory->asset('image', 'c', 'Fixture image legacy', ['scan_source' => 'Legacy scan']);
        $this->inventory->asset('image', 'd', 'Fixture image unscanned');
        $this->inventory->asset('container', 'e', 'Fixture container');

        $result = function (string $filter): array {
            $response = $this->api->assets(Request::create('/api/assets?q=Fixture&scan='.$filter));

            return json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR)['assets'];
        };
        $failed = $result('failed');
        self::assertSame(['Fixture image failed'], array_column($failed, 'name'));
        self::assertSame($success, $failed[0]['scanned_at']);
        self::assertSame($failure, $failed[0]['scan_attempted_at']);
        self::assertSame(['Fixture image legacy', 'Fixture image recovered'], array_column($result('recorded'), 'name'));
        self::assertSame(['Fixture image unscanned'], array_column($result('unscanned'), 'name'));

        $newer = $this->inventory->asset('image', 'newer', 'Fixture image newer failure');
        $this->store->db->insert('scan_schedules', [
            'id' => $newer, 'next_at' => 0, 'lease_until' => 0, 'interval_seconds' => 3600,
            'data' => Store::json(['attempted_at' => '2026-11-20T12:00:00+00:00', 'outcome' => 'failed']),
        ]);
        $this->inventory->asset('image', 'undated', 'Fixture image undated failure', ['scan_outcome' => 'failed']);
        $sorted = json_decode($this->api->assets(Request::create('/api/assets?sort=scan-failures'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('scan-failures', $sorted['sort']);
        self::assertSame([
            'Fixture image newer failure', 'Fixture image failed', 'Fixture image undated failure',
            'Fixture container', 'Fixture image legacy', 'Fixture image recovered', 'Fixture image unscanned',
        ], array_column($sorted['assets'], 'name'));
    }

    public function testRemediationsFilterByDisplayStatusAndExposeOnlyListFields(): void
    {
        $repository = $this->inventory->asset('repository', 'west-delivery', 'West delivery source');
        foreach (['release' => 'iac-image', 'binary' => 'standalone-binary'] as $id => $strategy) {
            $this->store->db->insert('changes', [
                'id' => $id,
                'asset_id' => 'release' === $id ? $repository : 'missing-asset',
                'finding_id' => 'finding',
                'status' => 'approved',
                'strategy' => $strategy,
                'created_at' => '2026-11-20T00:00:00+00:00',
                'data' => Store::json(['finding' => ['advisory' => 'PP-DEMO-001'], 'patch' => 'large diff']),
            ]);
        }
        $this->store->db->insert('release_tracking', [
            'id' => 'release',
            'next_at' => 0,
            'lease_until' => 0,
            'data' => Store::json(['result' => ['status' => 'verified']]),
        ]);

        $response = $this->api->remediations(Request::create('/api/remediations?status=release_verified'));
        $result = json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(['binary_approved', 'release_verified'], $result['statuses']);
        self::assertCount(1, $result['changes']);
        self::assertSame('release', $result['changes'][0]['id']);
        self::assertSame('PP-DEMO-001', $result['changes'][0]['title']);
        self::assertSame('West delivery source', $result['changes'][0]['asset_name']);
        self::assertSame('PP-DEMO-001', $result['changes'][0]['advisory']);
        self::assertSame('release-tracking', $result['changes'][0]['review_section']);
        self::assertSame(['iac-image', 'standalone-binary'], $result['strategies']);
        self::assertArrayNotHasKey('data', $result['changes'][0]);
        self::assertFalse($result['next']);

        $verified = json_decode($this->api->remediations(Request::create('/api/remediations?status=verified'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertCount(2, $verified['changes']);
        self::assertContains('verified', $verified['status_groups']);
        self::assertSame('binary-installation', array_column($verified['changes'], 'review_section', 'id')['binary']);

        $request = Request::create('/api/remediations', 'GET', [
            'status' => 'verified', 'strategy' => 'iac-image', 'month' => '2026-11', 'q' => 'WEST DELIVERY',
        ]);
        $byAssetAndStrategy = json_decode($this->api->remediations($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('iac-image', $byAssetAndStrategy['strategy']);
        self::assertSame(['release'], array_column($byAssetAndStrategy['changes'], 'id'));
        $request->query->set('strategy', 'standalone-binary');
        $otherStrategy = json_decode($this->api->remediations($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame([], $otherStrategy['changes']);

        foreach (['pp-demo-001' => 1, 'relea' => 1, '%' => 0, '_' => 0] as $search => $count) {
            $request = Request::create('/api/remediations?'.http_build_query(['status' => 'release_verified', 'q' => $search]));
            $filtered = json_decode($this->api->remediations($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
            self::assertSame($search, $filtered['search']);
            self::assertCount($count, $filtered['changes']);
        }

        foreach ([
            'running-image' => ['composer', 'deployed'],
            'installed-binary' => ['standalone-binary', 'deployed'],
            'staged-image' => ['composer', 'monitoring'],
            'waiting-approval' => ['composer', 'awaiting_approval'],
            'rolled-back' => ['composer', 'rolled_back'],
        ] as $id => [$strategy, $status]) {
            $this->store->db->insert('changes', [
                'id' => $id,
                'asset_id' => $repository,
                'finding_id' => 'finding',
                'status' => $status,
                'strategy' => $strategy,
                'created_at' => '2026-11-20T00:00:00+00:00',
                'data' => Store::json(['title' => $id]),
            ]);
        }
        $response = $this->api->remediations(Request::create('/api/remediations?status=deployment_verified'));
        $deployments = json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertContains('deployment_verified', $deployments['status_groups']);
        self::assertSame([
            'running-image' => 'deployed',
            'release' => 'release_verified',
            'installed-binary' => 'binary_deployed',
        ], array_column($deployments['changes'], 'display_status', 'id'));
    }

    public function testRemediationListOnlyLinksRecordedRetriesToTheirExistingFailedAttempt(): void
    {
        $original = str_repeat('a', 24);
        $base = [
            'asset_id' => str_repeat('1', 64), 'finding_id' => str_repeat('2', 64),
            'strategy' => 'composer', 'created_at' => '2026-11-20T00:00:00+00:00',
        ];
        $this->store->db->insert('changes', $base + ['id' => $original, 'status' => 'failed', 'data' => '{}']);
        foreach (['b' => $original, 'c' => str_repeat('f', 24), 'd' => $original] as $prefix => $previous) {
            $this->store->db->insert('changes', [
                'id' => str_repeat($prefix, 24), 'status' => 'queued',
                'asset_id' => 'd' === $prefix ? str_repeat('3', 64) : $base['asset_id'],
                'data' => Store::json(['retry_of' => $previous, 'title' => 'Review attempt '.$original]),
            ] + $base);
        }
        $response = $this->api->remediations(Request::create('/api/remediations?status=active'));
        $result = json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame([
            str_repeat('d', 24) => null, str_repeat('c', 24) => null, str_repeat('b', 24) => $original,
        ], array_column($result['changes'], 'retry_of', 'id'));

        $byId = $this->api->remediations(Request::create('/api/remediations?attempt='.strtoupper($original)));
        $exact = json_decode($byId->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame([$original], array_column($exact['changes'], 'id'));
        self::assertSame($original, $exact['attempt']);
        self::assertSame('execution-timeline', $exact['changes'][0]['review_section']);

        $hiddenRequest = Request::create('/api/remediations?status=active&selected_result='.$original);
        $hidden = json_decode($this->api->remediations($hiddenRequest)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($result['changes'], $hidden['changes']);
        self::assertSame($exact['changes'][0], $hidden['selected_change']);
        self::assertNull($hidden['selectedPage']);

        $hiddenRequest->query->set('executable', str_repeat('1', 64));
        $scoped = json_decode($this->api->remediations($hiddenRequest)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertNull($scoped['selected_change']);

        $visibleRequest = Request::create('/api/remediations?selected_result='.$original);
        $visible = json_decode($this->api->remediations($visibleRequest)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertNull($visible['selected_change']);
    }

    public function testFleetKeepsExactCountsWithBoundedPreviews(): void
    {
        $image = $this->inventory->asset('image', 'image', 'Image');
        $containers = [];
        for ($i = 0; $i < 22; ++$i) {
            $container = $this->inventory->asset('container', (string) $i, 'Container '.$i, ['running' => true]);
            $this->inventory->link($container, 'RUNS', $image, 'Fixture');
            $containers[$container] = 'Container '.$i;
        }
        $stopped = $this->inventory->asset('container', 'stopped', 'Stopped container', ['running' => false]);
        $this->inventory->link($stopped, 'RUNS', $image, 'Fixture');
        $pod = $this->inventory->asset('pod', 'fleet', 'Fleet pod');
        $workload = $this->inventory->asset('workload', 'fleet', 'Fleet workload');
        $repository = $this->inventory->asset('repository', 'fleet', 'Fleet source');
        $this->inventory->link($pod, 'HOSTS', $container, 'Fixture');
        $this->inventory->link($workload, 'HOSTS', $pod, 'Fixture');
        $this->inventory->link($image, 'BUILT_FROM', $repository, 'Fixture');
        $finding = [
            'advisory' => 'PP-FIXTURE-A', 'severity' => 'HIGH', 'type' => 'composer',
            'package' => 'fixture/dependency', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
        ];
        $this->inventory->findings($image, 'Fixture', [$finding]);
        $other = $this->inventory->asset('repository', 'unrelated', 'Unrelated source');
        $this->inventory->findings($other, 'Fixture', [array_replace($finding, ['package' => 'fixture/other'])]);

        $result = json_decode($this->api->fleet(Request::create('/api/fleet'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $group = $result['exposure'][0];
        self::assertSame(22, $group['running_count']);
        self::assertCount(20, $group['running']);
        self::assertTrue($group['fix_available']);
        self::assertArrayNotHasKey('findings', $group);

        $identity = ['PP-FIXTURE-A', 'fixture/dependency', 'composer'];
        $view = function (string $kind, array $query = []) use ($identity): ?array {
            $request = Request::create('/api/fleet', 'GET', [
                'impact_assets' => Store::json([...$identity, $kind]), 'impact_q' => 'fixture/other',
            ] + $query);
            $result = json_decode($this->api->fleet($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);

            return $result['impact_assets'];
        };
        $first = $view('container');
        self::assertSame(array_slice($containers, 0, 20, true), $first['assets']);
        self::assertSame(22, $first['asset_count']);
        self::assertSame(2, $first['last_page']);
        self::assertTrue($first['next']);
        $second = $view('container', ['impact_asset_page' => 2]);
        self::assertSame(array_slice($containers, 20, 2, true), $second['assets']);
        self::assertSame(21, $second['first_result']);
        self::assertFalse($second['next']);
        $search = $view('container', ['impact_asset_q' => 'CONTAINER 21']);
        self::assertSame([$container => 'Container 21'], $search['assets']);
        self::assertSame(1, $search['match_count']);
        self::assertSame([$container => 'Container 21'], $view('container', ['impact_asset_q' => $container])['assets']);
        self::assertSame([], $view('container', ['impact_asset_q' => $stopped])['assets']);
        self::assertSame([$workload => 'Fleet workload'], $view('workload')['assets']);
        self::assertSame([$repository => 'Fleet source'], $view('repository')['assets']);
        self::assertNull($view('unrecognized'));
    }

    public function testFleetPagesAndSearchesBeyondTheFirstAdvisoryImpactView(): void
    {
        $asset = $this->inventory->asset('image', 'fleet-limit', 'Fleet fixture');
        $findings = [];
        for ($index = 0; $index < 101; ++$index) {
            $findings[] = [
                'advisory' => 'PP-FIXTURE-'.$index, 'severity' => 'HIGH', 'type' => 'composer',
                'package' => 'fixture/dependency', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
            ];
        }
        $this->inventory->findings($asset, 'Fixture', $findings);

        $result = json_decode($this->api->fleet(Request::create('/api/fleet'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(101, $result['exposure_count']);
        self::assertCount(100, $result['exposure']);
        self::assertTrue($result['impact_next']);
        $second = json_decode($this->api->fleet(Request::create('/api/fleet?impact_page=2'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(2, $second['impact_page']);
        self::assertFalse($second['impact_next']);
        self::assertSame(['PP-FIXTURE-99'], array_column($second['exposure'], 'advisory'));
        $search = Request::create('/api/fleet', 'GET', ['impact_q' => 'DEPENDENCY pp-fixture-99 composer']);
        $filtered = json_decode($this->api->fleet($search)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(1, $filtered['exposure_count']);
        self::assertSame(['PP-FIXTURE-99'], array_column($filtered['exposure'], 'advisory'));

        $search->query->set('impact_running', '1');
        $unobserved = json_decode($this->api->fleet($search)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame([], $unobserved['exposure']);
        $container = $this->inventory->asset('container', 'running-fleet', 'Observed Fleet container', ['running' => true]);
        $this->inventory->link($container, 'RUNS', $asset, 'Fixture');
        $running = json_decode($this->api->fleet($search)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertTrue($running['impact_running']);
        self::assertSame(1, $running['exposure'][0]['running_count']);
    }

    public function testFleetSearchesBeyondTheSharedPackagePreview(): void
    {
        $components = [];
        for ($index = 0; $index < 100; ++$index) {
            $components[] = ['purl' => 'pkg:composer/fixture/library-'.$index, 'version' => '1.0'];
        }
        $components[] = ['purl' => 'pkg:composer/fixture/wanted', 'version' => '1.0'];
        foreach (['First', 'Second'] as $name) {
            $this->inventory->asset('image', $name, $name, ['sbom' => ['components' => $components]]);
        }

        $first = json_decode($this->api->fleet(Request::create('/api/fleet'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertTrue($first['package_next']);
        self::assertCount(100, $first['shared']);
        $second = json_decode($this->api->fleet(Request::create('/api/fleet?package_page=2'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertFalse($second['package_next']);
        self::assertSame(2, $second['package_page']);
        self::assertSame(['pkg:composer/fixture/wanted'], array_keys($second['shared']));
        $result = json_decode($this->api->fleet(Request::create('/api/fleet?package_q=WANTED'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(1, $result['shared_count']);
        self::assertSame(['pkg:composer/fixture/wanted'], array_keys($result['shared']));
        self::assertSame(2, $result['shared']['pkg:composer/fixture/wanted']['asset_count']);
    }

    public function testFleetPagesPackageAssetsAndFiltersAllObservedVersions(): void
    {
        $package = 'pkg:composer/fixture/catalog';
        foreach (array_reverse(range(1, 22)) as $index) {
            $versions = match ($index) {
                21 => array_map(static fn (int $version): string => '2.'.$version.'.0', range(1, 22)),
                22 => ['2026'],
                default => ['1.0.0'],
            };
            $name = sprintf('Catalog image %02d', $index);
            $components = array_map(static fn (string $version): array => ['purl' => $package.'@'.$version, 'version' => $version], $versions);
            $this->inventory->asset('image', $name, $name, ['sbom' => ['components' => $components]]);
        }
        $get = fn (array $filters): array => json_decode($this->api->fleet(Request::create('/api/fleet', 'GET', $filters))
            ->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $preview = $get([]);
        self::assertCount(20, $preview['shared'][$package]['assets']);
        self::assertNull($preview['dependency']);

        $first = $get(['dependency' => $package]);
        self::assertSame([], $first['shared']);
        self::assertSame(22, $first['dependency']['asset_count']);
        self::assertCount(20, $first['dependency']['assets']);
        self::assertTrue($first['dependency']['next']);
        $second = $get(['dependency' => $package, 'dependency_page' => 2])['dependency'];
        self::assertSame(['Catalog image 21', 'Catalog image 22'], array_column($second['assets'], 'name'));
        self::assertSame('2.22.0', $second['assets'][0]['versions'][21]);
        self::assertSame(['2026'], $second['assets'][1]['versions']);
        self::assertFalse($second['next']);

        $byVersion = $get(['dependency' => $package, 'dependency_version' => '2.22.0'])['dependency'];
        self::assertSame(1, $byVersion['match_count']);
        self::assertSame(['Catalog image 21'], array_column($byVersion['assets'], 'name'));
        $byName = $get(['dependency' => $package, 'dependency_version' => '2026', 'dependency_q' => 'IMAGE 22'])['dependency'];
        self::assertSame(['Catalog image 22'], array_column($byName['assets'], 'name'));
        self::assertFalse($get(['dependency' => 'pkg:composer/fixture/missing'])['dependency']['available']);
    }

    public function testFleetHistoryPagesRetainFullOutcomeTotals(): void
    {
        $start = new DateTimeImmutable('2026-11-01T00:00:00+00:00');
        for ($index = 0; $index <= 100; ++$index) {
            $this->store->db->insert('changes', [
                'id' => 'month-'.$index, 'asset_id' => 'fixture', 'finding_id' => 'fixture',
                'status' => 'failed', 'strategy' => 'composer', 'data' => '{}',
                'created_at' => $start->modify("-$index months")->format(DATE_ATOM),
            ]);
        }

        $first = json_decode($this->api->fleet(Request::create('/api/fleet'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertTrue($first['month_next']);
        self::assertCount(100, $first['history']['months']);
        $second = json_decode($this->api->fleet(Request::create('/api/fleet?month_page=2'))->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertFalse($second['month_next']);
        self::assertSame(['2018-07'], array_keys($second['history']['months']));
        self::assertSame(101, $second['history']['attempts']);
        self::assertSame(101, $second['month_count']);
        $fleetPath = '/fleet?package_q=shared&month_page=2#remediation-history';
        $request = Request::create('/api/remediations?'.http_build_query([
            'month' => '2018-07', 'status' => 'failed', 'fleet_from' => $fleetPath,
        ]));
        $records = json_decode($this->api->remediations($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('2018-07', $records['month']);
        self::assertSame($fleetPath, $records['fleet_from']);
        self::assertSame(['month-100'], array_column($records['changes'], 'id'));

        foreach (['/settings', '//example.com/fleet'] as $path) {
            $request = Request::create('/api/remediations?'.http_build_query(['fleet_from' => $path]));
            $records = json_decode($this->api->remediations($request)->getContent(), true, flags: JSON_THROW_ON_ERROR);
            self::assertNull($records['fleet_from']);
        }
    }
}
