<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Command\ScanScheduleCommand;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\AssetScans;
use App\Intelligence\ScanSchedules;
use App\Intelligence\Scanner;
use App\Queue\SchedulerActivity;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Messenger\MessageBus;

final class ScanSchedulesTest extends TestCase
{
    public function testFailedScanCanRetryThroughTheSchedulerWithoutChangingItsCadence(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $repository->temporary(function (string $directory) use ($store, $inventory, $repository): void {
            $scanner = $directory.'/trivy';
            file_put_contents($scanner, <<<'SH'
#!/bin/sh
if [ -f "$(dirname "$0")/fail" ]; then
    printf '%s\n' 'Scanner stderr fixture' >&2
    exit 1
fi
if [ "$1" = convert ]; then
    printf '%s' '{"bomFormat":"CycloneDX","components":[]}'
else
    printf '%s' '{"SchemaVersion":2,"Results":[]}'
fi
SH);
            chmod($scanner, 0700);
            $scans = new AssetScans($inventory, $repository, new Infrastructure($inventory, $store),
                new Scanner($inventory, $store, $scanner), $store);
            $schedules = new ScanSchedules($store, $inventory, $scans);
            $activity = new SchedulerActivity($store);
            $command = new CommandTester(new ScanScheduleCommand($schedules, new Connections($store, new MessageBus()), $activity));
            $arguments = ['action' => 'run-due', '--limit' => '1'];
            $image = 'fixture.example/image@sha256:'.str_repeat('1', 64);
            $asset = $scans->registerRegistryImage($image, 'linux/amd64', null);
            $inventory->asset('image', $image.'#linux/amd64', $image, ['scan_source' => 'Previous fixture scan']);
            $schedules->add($asset, 60);
            touch($directory.'/fail');

            self::assertSame(Command::FAILURE, $command->execute($arguments));
            self::assertJsonStringEqualsJsonString(Store::json([$asset => 'failed']), $command->getDisplay());
            $failedRun = $activity->latest(SchedulerActivity::SCANS);
            self::assertSame('completed', $failedRun['status']);
            self::assertSame(['total' => 1, 'passed' => 0, 'failed' => 1, 'queued' => 0], $failedRun['counts']);
            $failure = $schedules->all()[0];
            self::assertStringContainsString('Check the image digest, registry access', $failure['data']['failure_reason']);
            self::assertStringNotContainsString('Scanner stderr fixture', $failure['data']['failure_reason']);
            self::assertSame('Previous fixture scan', $inventory->get($asset)['data']['scan_source']);
            self::assertGreaterThan(time(), $failure['next_at']);
            self::assertTrue($schedules->requestRetry($asset));
            self::assertFalse($schedules->requestRetry($asset));
            $due = $schedules->all()[0];
            self::assertLessThanOrEqual(time(), $due['next_at']);
            self::assertSame($failure['data'], $due['data']);
            self::assertSame($failure['interval_seconds'], $due['interval_seconds']);

            unlink($directory.'/fail');
            self::assertSame(Command::SUCCESS, $command->execute($arguments));
            self::assertJsonStringEqualsJsonString(Store::json([$asset => 'passed']), $command->getDisplay());
            self::assertSame(['total' => 1, 'passed' => 1, 'failed' => 0, 'queued' => 0],
                $activity->latest(SchedulerActivity::SCANS)['counts']);
            $result = $schedules->all()[0];
            self::assertSame('Trivy', $inventory->get($asset)['data']['scan_source']);
            self::assertArrayNotHasKey('failure_reason', $result['data']);
            self::assertSame(3600, $result['interval_seconds']);
            self::assertGreaterThan(time(), $result['next_at']);
            $this->expectExceptionMessage('The latest scheduled scan does not need a retry.');
            $schedules->requestRetry($asset);
        });
    }

    public function testCannotBringARunningScanDue(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $schedules = new ScanSchedules($store, $inventory, new AssetScans($inventory, new Repository($inventory),
            new Infrastructure($inventory, $store), new Scanner($inventory, $store, 'unused'), $store));
        $asset = $inventory->asset('image', 'fixture', 'Fixture');
        $now = time();
        $store->db->insert('scan_schedules', [
            'id' => $asset, 'next_at' => $now + 600, 'lease_until' => $now + 120, 'interval_seconds' => 3600,
            'data' => Store::json(['outcome' => 'failed']),
        ]);
        $this->expectExceptionMessage('This scan is already running.');
        try {
            $schedules->requestRetry($asset);
        } finally {
            $row = $schedules->all()[0];
            self::assertSame($now + 600, $row['next_at']);
            self::assertSame($now + 120, $row['lease_until']);
        }
    }
}
