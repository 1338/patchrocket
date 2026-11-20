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
        $image = $inventory->asset('image', 'fixture-image', 'Fixture image');
        $container = $inventory->asset('container', 'fixture-runtime', 'Running fixture', ['running' => true]);
        $inventory->link($container, 'RUNS', $image, 'Docker');
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
        self::assertSame([$container => 'Running fixture'], $group['running']);
        self::assertSame([$repository => 'Fixture source'], $group['repositories']);
        self::assertCount(2, $group['findings']);
    }
}
