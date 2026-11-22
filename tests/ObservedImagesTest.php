<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\AssetScans;
use App\Intelligence\Scanner;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class ObservedImagesTest extends TestCase
{
    public function testScopedRegistrySelectionDeduplicatesRunningDigestsAndSkipsSuccessfulScans(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $scans = new AssetScans($inventory, new Repository($inventory), new Infrastructure($inventory, $store), new Scanner($inventory, $store, 'trivy'), $store);

        $one = 'registry.example/app@sha256:'.str_repeat('a', 64);
        $two = 'registry.example/app@sha256:'.str_repeat('b', 64);
        $image = $inventory->asset('image', $one, 'App', ['digest' => $one]);
        $scannedImage = $inventory->asset('image', $two, 'Scanned', ['digest' => $two, 'scan_source' => 'Trivy']);
        foreach (['app-a', 'app-b'] as $name) {
            $runtime = $inventory->asset('container', $name, $name, ['running' => true, 'scope' => 'aks/apps']);
            $inventory->link($runtime, 'RUNS', $image, 'Fixture');
            $inventory->link($runtime, 'RUNS', $scannedImage, 'Fixture');
        }

        self::assertSame([$image => 'App'], iterator_to_array($scans->runningImages(['registry.example'], 'aks/apps', false)));
        self::assertCount(2, iterator_to_array($scans->runningImages(['registry.example'], 'aks/apps', true)));
        self::assertSame([], iterator_to_array($scans->runningImages(['registry.example'], 'aks/different', true)));
        self::assertSame([], iterator_to_array($scans->runningImages(['other.example'], 'aks/apps', true)));
    }

    public function testMultipleExactScopesSelectEachDigestOnce(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $scans = new AssetScans($inventory, new Repository($inventory), new Infrastructure($inventory, $store), new Scanner($inventory, $store, 'trivy'), $store);
        $images = [];
        foreach ([
            'Shared' => ['aks/apps', 'aks/payments'],
            'Payments only' => ['aks/payments'],
            'Different namespace' => ['aks/apps-preview'],
            'Different context' => ['other/apps', 'aks/other/apps'],
        ] as $name => $scopes) {
            $digest = 'registry.example/app@sha256:'.hash('sha256', $name);
            $images[$name] = $inventory->asset('image', $digest, $name, ['digest' => $digest]);
            foreach ($scopes as $scope) {
                $runtime = $inventory->asset('container', $scope.'/'.$name, $name, ['running' => true, 'scope' => $scope]);
                $inventory->link($runtime, 'RUNS', $images[$name], 'Fixture');
            }
        }

        self::assertSame([
            $images['Payments only'] => 'Payments only',
            $images['Shared'] => 'Shared',
        ], iterator_to_array($scans->runningImages(['registry.example'], null, false, scopes: ['aks/apps', 'aks/payments'])));
        self::assertSame([], iterator_to_array($scans->runningImages(['registry.example'], null, false, scopes: [])));
    }
}
