<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\MessageBus;

final class ConnectionScanSchedulesTest extends TestCase
{
    public function testFollowUpScanStatusOnlyUsesEvidenceForTheSamePackageUpdate(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $id = $connections->save('vm', ['name' => 'VM fixture', 'target' => 'fixture@vm.example.invalid', 'credential' => 'fixture:ssh']);
        $attempt = str_repeat('a', 32);
        $connections->run($id, 'scan', afterPackageUpdate: $attempt);
        $row = $connections->get($id);
        self::assertSame(['busy' => true, 'status' => 'queued', 'finished_at' => null, 'failure_reason' => null],
            $connections->packageScanStatus($row['data'], $attempt));
        self::assertNull($connections->packageScanStatus($row['data'], str_repeat('b', 32))['status']);
        $expired = array_replace($row['data'], ['status' => 'running', 'queued_at' => time() - 3601]);
        self::assertSame('overdue', $connections->packageScanStatus($expired, $attempt)['status']);
        $record = ['status' => 'failed', 'finished_at' => gmdate(DATE_ATOM), 'failure_reason' => 'Fixture scan failed.',
            'after_package_update' => $attempt];
        $connections->update($row, array_replace($row['data'], ['status' => 'failed', 'last_scan' => $record]));
        $connections->run($id, 'discover');
        $latest = $connections->get($id)['data'];
        self::assertArrayNotHasKey('scan_after_package_update', $latest);
        self::assertSame('Fixture scan failed.', $connections->packageScanStatus($latest, $attempt)['failure_reason']);
        self::assertNull($connections->packageScanStatus($latest, str_repeat('b', 32))['failure_reason']);
    }

    public function testScheduleSnapshotMatchesDispatcherEligibility(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $now = time();
        $finishedAt = gmdate(DATE_ATOM, $now - 3600);
        foreach ([
            'due' => ['next_at' => $now - 60, 'status' => 'failed', 'operation' => 'scan', 'finished_at' => $finishedAt,
                'result' => 'The checkout directory is unavailable.'],
            'busy' => ['next_at' => $now - 180, 'status' => 'queued', 'operation' => 'discover', 'queued_at' => $now - 10],
            'expired' => ['next_at' => $now - 120, 'status' => 'running', 'operation' => 'discover', 'queued_at' => $now - 3600],
            'future' => ['next_at' => $now + 60],
            'legacy' => [],
            'manual' => ['interval' => 0, 'next_at' => 0],
        ] as $id => $settings) {
            $store->db->insert('inventory_connections', [
                'id' => $id, 'name' => $id, 'kind' => 'repository',
                'data' => Store::json($settings + ['interval' => 60, 'credential' => 'fixture:repository']),
            ]);
        }

        $snapshot = $connections->scheduledScans($now);
        $rows = array_column($snapshot['rows'], null, 'id');
        self::assertSame(5, $snapshot['total']);
        self::assertSame(2, $snapshot['due_count']);
        self::assertSame($now - 120, $snapshot['oldest_due']);
        self::assertSame(['expired', 'due', 'busy', 'future', 'legacy'], array_keys($rows));
        self::assertSame('failed', $rows['due']['outcome']);
        self::assertNull($rows['due']['failure_reason']);
        self::assertSame('The checkout directory is unavailable.',
            array_column($connections->scheduledScans($now, true)['rows'], null, 'id')['due']['failure_reason']);
        self::assertSame('queued', $rows['busy']['state']);
        self::assertSame($now - 10, $rows['busy']['queued_at']);
        self::assertNull($rows['expired']['queued_at']);
        self::assertNull($rows['legacy']['queued_at']);
        self::assertNull($rows['busy']['outcome']);
        self::assertArrayNotHasKey('credential', $rows['due']);
        self::assertSame(['due' => 'queued', 'expired' => 'queued'], $connections->enqueueDue(10));
        $queued = $connections->scheduledScans(time(), true);
        self::assertSame(0, $queued['due_count']);
        $rows = array_column($queued['rows'], null, 'id');
        self::assertSame('failed', $rows['due']['outcome']);
        self::assertSame($finishedAt, $rows['due']['checked_at']);
        self::assertSame('The checkout directory is unavailable.', $rows['due']['failure_reason']);
    }

    public function testConnectionEditsKeepDueScansUntilTheIntervalChanges(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $settings = ['name' => 'Source', 'target' => '/fixture/source'];
        $id = $connections->save('repository', $settings + ['interval' => 60]);
        $row = $connections->get($id);
        $dueAt = time() - 60;
        $connections->update($row, array_replace($row['data'], ['next_at' => $dueAt, 'interval' => '60']));

        $settings = array_replace($settings, ['id' => $id, 'name' => 'Renamed source']);
        $connections->save('repository', $settings + ['interval' => '60']);
        self::assertSame($dueAt, $connections->scheduledScans(time())['oldest_due']);
        $connections->save('repository', $settings);
        self::assertSame($dueAt, $connections->scheduledScans(time())['oldest_due']);

        $before = time();
        $connections->save('repository', $settings + ['interval' => 120]);
        $schedule = $connections->scheduledScans(time());
        self::assertSame(0, $schedule['due_count']);
        self::assertGreaterThanOrEqual($before + 7200, $schedule['rows'][0]['next_at']);
        self::assertLessThanOrEqual(time() + 7200, $schedule['rows'][0]['next_at']);

        $connections->save('repository', $settings + ['interval' => 0]);
        self::assertSame(0, $connections->get($id)['data']['next_at']);
        self::assertSame(0, $connections->scheduledScans(time())['total']);
    }

    public function testCadenceEditsKeepScanResultAndScopeEditsInvalidateIt(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $settings = ['name' => 'Source', 'target' => '/fixture/source', 'interval' => 60];
        $id = $connections->save('repository', $settings);
        $row = $connections->get($id);
        $finishedAt = gmdate(DATE_ATOM);
        $connections->update($row, array_replace($row['data'], [
            'operation' => 'scan', 'status' => 'failed', 'finished_at' => $finishedAt,
            'last_scan' => ['status' => 'failed', 'finished_at' => $finishedAt], 'result' => 'Manifest is unavailable.',
        ]));

        self::assertSame('Manifest is unavailable.', $connections->scheduledScans(time(), true)['rows'][0]['failure_reason']);
        $connections->save('repository', array_replace($settings, ['id' => $id, 'name' => 'Renamed source', 'interval' => 120]));
        self::assertSame('Manifest is unavailable.', $connections->get($id)['data']['last_scan']['failure_reason']);
        self::assertSame($finishedAt, $connections->scheduledScans(time())['rows'][0]['checked_at']);
        $connections->save('repository', array_replace($settings, ['id' => $id, 'subdirectory' => 'app']));
        $changed = $connections->scheduledScans(time(), true)['rows'][0];
        self::assertNull($changed['outcome']);
        self::assertNull($changed['checked_at']);
        self::assertNull($changed['failure_reason']);
        self::assertSame('failed', $connections->get($id)['data']['status']);

        $row = $connections->get($id);
        $connections->update($row, array_replace($row['data'], [
            'status' => 'running', 'token' => 'stale-scan', 'queued_at' => time() - 3601,
        ]));
        $connections->save('repository', array_replace($settings, ['id' => $id, 'target' => '/fixture/other']));
        self::assertArrayNotHasKey('token', $connections->get($id)['data']);
    }
}
