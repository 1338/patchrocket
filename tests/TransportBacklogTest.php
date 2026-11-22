<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Queue\TransportBacklog;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Bridge\Doctrine\Transport\Connection;

final class TransportBacklogTest extends TestCase
{
    public function testItSeparatesCurrentClaimsFromWorkEligibleForRedelivery(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        (new Connection(['queue_name' => 'patches'], $connection))->setup();
        $backlog = new TransportBacklog(new Store($connection));
        $now = 1800000000;
        $cutoff = $now - TransportBacklog::REDELIVERY_SECONDS;
        foreach ([
            [$now - 120, null],
            [$now, null],
            [$now + 45, null],
            [$now + 30, $cutoff - 20],
            [$cutoff - 300, $cutoff],
            [$cutoff - 300, $now - 20],
            [$cutoff - 300, $cutoff - 1],
        ] as [$availableAt, $claim]) {
            $connection->insert('messenger_messages', [
                'queue_name' => 'patches', 'body' => 'fixture', 'headers' => '{}',
                'created_at' => gmdate('Y-m-d H:i:s', $cutoff - 300),
                'available_at' => gmdate('Y-m-d H:i:s', $availableAt),
                'delivered_at' => null === $claim ? null : gmdate('Y-m-d H:i:s', $claim),
            ]);
        }

        self::assertSame([
            'total' => 7, 'ready' => 2, 'delayed' => 2, 'claimed' => 2, 'redeliverable' => 1,
            'oldest_ready' => $now - 120, 'next_delayed' => $now + 30, 'oldest_claim' => $cutoff, 'oldest_redelivery' => $now,
        ], $backlog->snapshot($now)['patches']);
        $next = $backlog->snapshot($now + 1)['patches'];
        self::assertSame(1, $next['claimed']);
        self::assertSame(2, $next['redeliverable']);
        self::assertSame($now - 20, $next['oldest_claim']);

        $connection->insert('messenger_messages', [
            'queue_name' => 'kubernetes_checks', 'body' => 'fixture', 'headers' => '{}',
            'created_at' => gmdate('Y-m-d H:i:s', $cutoff - 300),
            'available_at' => gmdate('Y-m-d H:i:s', $now + 30),
            'delivered_at' => gmdate('Y-m-d H:i:s', $cutoff - 60),
        ]);
        $waiting = $backlog->snapshot($now + 29)['kubernetes_checks'];
        self::assertSame(1, $waiting['delayed']);
        self::assertNull($waiting['oldest_redelivery']);
        $due = $backlog->snapshot($now + 30)['kubernetes_checks'];
        self::assertSame(1, $due['redeliverable']);
        self::assertSame($now + 30, $due['oldest_redelivery']);
    }
}
