<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\MessageBus;

final class InventoryConnectionJobsTest extends TestCase
{
    public function testPagingAndFiltersReachOlderLatestJobsWithoutExposingDiagnostics(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $now = 1700000000;
        for ($index = 1; $index <= 101; ++$index) {
            $store->db->insert('inventory_connections', [
                'id' => hash('sha256', 'batch-'.$index), 'name' => sprintf('Batch target %03d', $index), 'kind' => 'repository',
                'data' => Store::json(['status' => 'complete', 'operation' => 'scan', 'queued_at' => $now - $index]),
            ]);
        }
        $id = substr(hash('sha256', 'archive'), 0, 32);
        $store->db->insert('inventory_connections', [
            'id' => $id, 'name' => 'Archive %_ source', 'kind' => 'repository',
            'data' => Store::json(['status' => 'failed', 'operation' => 'discover', 'queued_at' => $now - 500,
                'result' => 'Private checkout diagnostic']),
        ]);

        $first = $connections->inventoryJobs($now, '', '', '', '', 1, false);
        self::assertCount(50, $first['rows']);
        self::assertTrue($first['next']);
        $third = $connections->inventoryJobs($now, '', '', '', '', 3, false);
        self::assertSame(['Batch target 101', 'Archive %_ source'], array_column($third['rows'], 'name'));
        self::assertFalse($third['next']);

        $search = $connections->inventoryJobs($now, 'failed', 'discover', ' ARCHIVE %_ ', '', 1, false);
        self::assertSame([$id], array_column($search['rows'], 'id'));
        self::assertNull($search['rows'][0]['result']);
        self::assertSame([], $connections->inventoryJobs($now, '', 'scan', '', $id, 1, true)['rows']);
        self::assertSame([$id], array_column($connections->inventoryJobs($now, '', '', '%_', '', 1, false)['rows'], 'id'));
        self::assertSame([$id], array_column($connections->inventoryJobs($now, '', '', strtoupper($id), '', 1, false)['rows'], 'id'));
        self::assertSame('Private checkout diagnostic', $connections->inventoryJobs($now, '', '', '', $id, 1, true)['rows'][0]['result']);
        $imported = hash('sha256', 'batch-101');
        self::assertSame([$imported], array_column($connections->inventoryJobs($now, '', '', '', $imported, 1, false)['rows'], 'id'));
    }

    public function testOverdueUsesTheActiveWindowWithoutChangingTheRecordedStatus(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $now = 1700000000;
        foreach ([
            'queued' => ['status' => 'queued', 'queued_at' => $now - 3599],
            'running' => ['status' => 'running', 'queued_at' => $now - 3599],
            'expired' => ['status' => 'running', 'queued_at' => $now - 3600],
            'missing timestamp' => ['status' => 'queued'],
            'completed' => ['status' => 'complete', 'queued_at' => $now - 7200],
        ] as $name => $data) {
            $store->db->insert('inventory_connections', [
                'id' => hash('sha256', $name), 'name' => $name, 'kind' => 'repository',
                'data' => Store::json($data + ['operation' => 'discover']),
            ]);
        }

        $running = $connections->inventoryJobs($now, 'running', '', '', '', 1, false);
        self::assertSame(['running'], array_column($running['rows'], 'name'));
        self::assertSame(2, $running['overdue_count']);
        $overdue = $connections->inventoryJobs($now, 'overdue', 'discover', '', '', 1, false)['rows'];
        self::assertSame(['expired', 'missing timestamp'], array_column($overdue, 'name'));
        self::assertSame(['running', 'queued'], array_column($overdue, 'status'));
        self::assertSame(['overdue', 'overdue'], array_column($overdue, 'state'));
        self::assertSame($now, (int) $overdue[0]['expires_at']);
        self::assertNull($overdue[1]['expires_at']);
        self::assertSame('running', $connections->get($overdue[0]['id'])['data']['status']);
    }
}
