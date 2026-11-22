<?php
declare(strict_types=1);

namespace App\Queue;

use App\Audit\Store;

final class TransportBacklog
{
    public const REDELIVERY_SECONDS = 3600;
    public const EMPTY_QUEUE = [
        'total' => 0, 'ready' => 0, 'delayed' => 0, 'claimed' => 0, 'redeliverable' => 0,
        'oldest_ready' => null, 'next_delayed' => null, 'oldest_claim' => null, 'oldest_redelivery' => null,
    ];

    public function __construct(private readonly Store $store)
    {
    }

    public function snapshot(int $now): array
    {
        // The transport accepts a claim strictly older than the cutoff at whole-second precision.
        $claimExpires = $this->store->db->getDatabasePlatform()->getDateAddSecondsExpression('delivered_at', (string) (self::REDELIVERY_SECONDS + 1));
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT queue_name, COUNT(*) AS total,
                SUM(CASE WHEN state = 'ready' THEN 1 ELSE 0 END) AS ready,
                SUM(CASE WHEN state = 'delayed' THEN 1 ELSE 0 END) AS delayed,
                SUM(CASE WHEN state = 'claimed' THEN 1 ELSE 0 END) AS claimed,
                SUM(CASE WHEN state = 'redeliverable' THEN 1 ELSE 0 END) AS redeliverable,
                MIN(CASE WHEN state = 'ready' THEN available_at END) AS oldest_ready,
                MIN(CASE WHEN state = 'delayed' THEN available_at END) AS next_delayed,
                MIN(CASE WHEN state = 'claimed' THEN delivered_at END) AS oldest_claim,
                MIN(CASE WHEN state = 'redeliverable'
                    THEN CASE WHEN available_at > $claimExpires THEN available_at ELSE $claimExpires END
                END) AS oldest_redelivery
             FROM (
                SELECT queue_name, available_at, delivered_at,
                    CASE WHEN delivered_at >= ? THEN 'claimed'
                         WHEN available_at > ? THEN 'delayed'
                         WHEN delivered_at IS NOT NULL THEN 'redeliverable'
                         ELSE 'ready' END AS state
                FROM messenger_messages
             ) messages GROUP BY queue_name",
            [gmdate('Y-m-d H:i:s', $now - self::REDELIVERY_SECONDS), gmdate('Y-m-d H:i:s', $now)],
        );
        $queues = [];
        foreach ($rows as $row) {
            foreach (['total', 'ready', 'delayed', 'claimed', 'redeliverable'] as $field) {
                $row[$field] = (int) $row[$field];
            }
            foreach (['oldest_ready', 'next_delayed', 'oldest_claim', 'oldest_redelivery'] as $field) {
                $row[$field] = null === $row[$field] ? null : (new \DateTimeImmutable($row[$field], new \DateTimeZone('UTC')))->getTimestamp();
            }
            $queue = $row['queue_name'];
            unset($row['queue_name']);
            $queues[$queue] = $row;
        }

        return $queues;
    }
}
