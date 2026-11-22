<?php
declare(strict_types=1);

namespace App\Queue;

use App\Audit\Store;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Messenger\Event\WorkerRunningEvent;
use Symfony\Component\Messenger\Event\WorkerStartedEvent;
use Symfony\Component\Messenger\Event\WorkerStoppedEvent;

final class WorkerPresence
{
    public const RECENT_SECONDS = 45;
    private const HISTORY_SECONDS = 86400;
    private const PAGE_SIZE = 50;

    private ?string $worker = null;
    private int $lastSeen = 0;
    private array $transports = [];

    public function __construct(private readonly Store $store)
    {
    }

    public function recentTransports(int $now): array
    {
        return array_keys($this->recentCounts($now));
    }

    /** @return array<string, int> */
    public function recentCounts(int $now): array
    {
        $counts = [];
        foreach ($this->heartbeats($now - self::RECENT_SECONDS + 1) as $row) {
            if (!$row['data']['stopped']) {
                foreach (array_unique($row['data']['transports']) as $transport) {
                    $counts[$transport] = ($counts[$transport] ?? 0) + 1;
                }
            }
        }

        return $counts;
    }

    public function dashboardPage(int $now, string $transport, int $page): array
    {
        $offset = ($page - 1) * self::PAGE_SIZE;
        $workers = [];
        foreach ($this->heartbeats($now - self::HISTORY_SECONDS) as $row) {
            $worker = $row['data'];
            if ('' !== $transport && !in_array($transport, $worker['transports'], true)) {
                continue;
            }
            if ($offset > 0) {
                --$offset;
                continue;
            }
            if (count($workers) === self::PAGE_SIZE) {
                return ['rows' => $workers, 'next' => true];
            }
            $workers[] = $worker + [
                'id' => $row['id'],
                'state' => match (true) {
                    $worker['stopped'] => 'Stopped',
                    $now - $worker['seen'] < self::RECENT_SECONDS => 'Recently seen',
                    default => 'Heartbeat overdue',
                },
            ];
        }

        return ['rows' => $workers, 'next' => false];
    }

    private function heartbeats(int $since): iterable
    {
        $seen = $this->store->jsonText('data', 'seen');
        return $this->store->iterate("SELECT id, data FROM operator_settings WHERE id LIKE 'worker-presence:%'
            AND CAST($seen AS BIGINT) >= ? ORDER BY CAST($seen AS BIGINT) DESC, id", [$since]);
    }

    #[AsEventListener]
    public function started(WorkerStartedEvent $event): void
    {
        $this->worker = 'worker-presence:'.bin2hex(random_bytes(12));
        $this->transports = $event->getWorker()->getMetadata()->getTransportNames();
        $this->record();
    }

    #[AsEventListener]
    public function running(WorkerRunningEvent $event): void
    {
        if (time() - $this->lastSeen >= 15) {
            $this->record();
        }
    }

    #[AsEventListener]
    public function stopped(WorkerStoppedEvent $event): void
    {
        $this->record(stopped: true);
    }

    private function record(bool $stopped = false): void
    {
        if (null === $this->worker) {
            return;
        }
        $this->lastSeen = time();
        try {
            $this->store->db->executeStatement(
                'INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO UPDATE SET data = excluded.data',
                [$this->worker, Store::json([
                    'host' => gethostname() ?: 'Worker', 'transports' => $this->transports,
                    'seen' => $this->lastSeen, 'stopped' => $stopped,
                ])],
            );
            $seen = $this->store->jsonText('data', 'seen');
            $this->store->db->executeStatement(
                "DELETE FROM operator_settings WHERE id LIKE 'worker-presence:%' AND CAST($seen AS BIGINT) < ?",
                [$this->lastSeen - self::HISTORY_SECONDS],
            );
        } catch (\Doctrine\DBAL\Exception) {
            // Worker health reporting should not interrupt work during a database outage.
        }
    }
}
