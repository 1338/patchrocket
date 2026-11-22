<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Queue\WorkerPresence;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class WorkerPresenceTest extends TestCase
{
    public function testRecentTransportsExcludeOverdueAndStoppedWorkers(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $workers = new WorkerPresence($store);
        $now = 1700000000;
        self::assertSame([], $workers->recentTransports($now));

        foreach ([
            ['jobs', $now - WorkerPresence::RECENT_SECONDS + 1, false],
            ['jobs', $now - 1, false],
            ['kubernetes_checks', $now - WorkerPresence::RECENT_SECONDS, false],
            ['kubernetes_checks', $now - 1, true],
        ] as $id => [$transport, $seen, $stopped]) {
            $store->db->insert('operator_settings', ['id' => 'worker-presence:'.$id, 'data' => Store::json([
                'host' => 'test-worker', 'transports' => [$transport], 'seen' => $seen, 'stopped' => $stopped,
            ])]);
        }

        self::assertSame(['jobs'], $workers->recentTransports($now));
    }

    public function testDashboardPagesDoNotLimitRecentCountsAndFilterBeforePaging(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $presence = new WorkerPresence($store);
        $now = 1700000000;
        $save = static function (string $id, array $transports, int $seen, bool $stopped = false) use ($store): void {
            $store->db->insert('operator_settings', ['id' => 'worker-presence:'.$id, 'data' => Store::json([
                'host' => $id, 'transports' => $transports, 'seen' => $seen, 'stopped' => $stopped,
            ])]);
        };
        for ($index = 1; $index <= 51; ++$index) {
            $save(sprintf('jobs-%02d', $index), ['jobs'], $now - 1);
        }
        $save('shared', ['jobs', 'kubernetes_checks', 'kubernetes_checks'], $now - 2);
        $save('stopped', ['kubernetes_checks'], $now - 10, true);
        $save('overdue', ['kubernetes_checks'], $now - WorkerPresence::RECENT_SECONDS);
        $save('expired', ['kubernetes_checks'], $now - 86401);

        self::assertSame(['jobs' => 52, 'kubernetes_checks' => 1], $presence->recentCounts($now));
        $first = $presence->dashboardPage($now, '', 1);
        self::assertCount(50, $first['rows']);
        self::assertTrue($first['next']);
        $second = $presence->dashboardPage($now, '', 2);
        self::assertSame(['jobs-51', 'shared', 'stopped', 'overdue'], array_column($second['rows'], 'host'));
        self::assertFalse($second['next']);
        $checks = $presence->dashboardPage($now, 'kubernetes_checks', 1);
        self::assertSame(['shared', 'stopped', 'overdue'], array_column($checks['rows'], 'host'));
        self::assertSame(['Recently seen', 'Stopped', 'Heartbeat overdue'], array_column($checks['rows'], 'state'));
        self::assertFalse($checks['next']);
    }
}
