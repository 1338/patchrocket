<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Fleet\Analysis;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class FleetAnalysisTest extends TestCase
{
    public function testRunningExposureRequiresAnObservedFindingOnTheImage(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $repository = $inventory->asset('repository', 'fixture', 'Fixture source');
        $digest = 'sha256:'.str_repeat('a', 64);
        $image = $inventory->asset('image', 'fixture-image', 'Fixture image', ['digest' => $digest]);
        $alias = $inventory->asset('image', 'fixture-alias', 'Observed image', ['digest' => $digest]);
        $other = $inventory->asset('image', 'other', 'Other image', ['digest' => 'sha256:'.str_repeat('b', 64)]);
        $container = $inventory->asset('container', 'fixture-runtime', 'Running fixture', ['running' => true]);
        $remote = $inventory->asset('container', 'fixture-remote', 'Running through digest match', ['running' => true]);
        $stopped = $inventory->asset('container', 'fixture-stopped', 'Stopped fixture', ['running' => false]);
        $unrelated = $inventory->asset('container', 'fixture-unrelated', 'Unrelated container', ['running' => true]);
        $pod = $inventory->asset('pod', 'fixture-pod', 'Fixture pod');
        $workload = $inventory->asset('workload', 'fixture-workload', 'Fixture workload');
        $inventory->link($container, 'RUNS', $image, 'Docker');
        $inventory->link($container, 'RUNS', $alias, 'Docker');
        $inventory->link($remote, 'RUNS', $alias, 'Kubernetes');
        $inventory->link($stopped, 'RUNS', $alias, 'Kubernetes');
        $inventory->link($unrelated, 'RUNS', $other, 'Docker');
        $inventory->link($pod, 'HOSTS', $remote, 'Kubernetes');
        $inventory->link($workload, 'HOSTS', $pod, 'Kubernetes');
        $inventory->link($image, 'BUILT_FROM', $repository, 'Operator association');
        $finding = [
            'advisory' => 'PP-FIXTURE-A', 'severity' => 'HIGH', 'type' => 'composer',
            'package' => 'fixture/dependency', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
        ];
        $inventory->findings($repository, 'Fixture', [$finding]);
        $analysis = new Analysis($store);

        self::assertSame([], $analysis->report()['exposure'][0]['running']);

        $inventory->findings($image, 'Fixture', [$finding]);
        $group = $analysis->report()['exposure'][0];
        self::assertCount(2, $group['running']);
        self::assertSame('Running fixture', $group['running'][$container]);
        self::assertSame('Running through digest match', $group['running'][$remote]);
        self::assertSame([$workload => 'Fixture workload'], $group['workloads']);
        self::assertSame(305, $group['priority']);
        self::assertSame([$repository => 'Fixture source'], $group['repositories']);
        self::assertCount(2, $group['findings']);

        $group['findings'] = [];
        self::assertSame($group, $analysis->report(includeFindings: false)['exposure'][0]);

        $unlinkedImage = $inventory->asset('image', 'scan-only', 'Scanned image record', ['digest' => $digest]);
        $inventory->findings($image, 'Fixture', []);
        $inventory->findings($unlinkedImage, 'Fixture', [$finding]);
        self::assertEquals($group['running'], $analysis->report()['exposure'][0]['running']);
    }
}
