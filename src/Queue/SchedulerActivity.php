<?php
declare(strict_types=1);

namespace App\Queue;

use App\Audit\Store;
use Doctrine\DBAL\Exception;

final class SchedulerActivity
{
    public const RELEASES = 'release-poller';
    public const SCANS = 'scan-scheduler';

    public function __construct(private readonly Store $store)
    {
    }

    /**
     * @template T
     * @param callable(): T $work
     * @param list<string> $outcomes
     * @return T
     */
    public function run(string $id, callable $work, array $outcomes = []): mixed
    {
        $time = time();
        $started = Store::json(['started_at' => $time, 'run' => bin2hex(random_bytes(12)), 'status' => 'running']);
        try {
            $this->store->put('operator_settings', ['id' => $id, 'data' => $started]);
        } catch (Exception) {
            // Observing the scheduler must not prevent it from running.
            $started = null;
        }

        $status = 'failed';
        $counts = null;
        try {
            $result = $work();
            $status = 'completed';
            if (is_array($result)) {
                $counts = ['total' => count($result)];
                if ($outcomes) {
                    $tally = array_count_values(array_filter($result, is_string(...)));
                    $buckets = array_fill_keys($outcomes, 0);
                    $counts += array_replace($buckets, array_intersect_key($tally, $buckets));
                }
            }

            return $result;
        } finally {
            if (null !== $started) {
                try {
                    $finished = [
                        'started_at' => $time, 'finished_at' => time(), 'status' => $status,
                    ];
                    if (null !== $counts) {
                        $finished['counts'] = $counts;
                    }
                    $this->store->db->update('operator_settings', ['data' => Store::json($finished)], ['id' => $id, 'data' => $started]);
                } catch (Exception) {
                    // Preserve the scheduler outcome when its observation cannot be saved.
                }
            }
        }
    }

    public function latest(string $id): ?array
    {
        $data = $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [$id])['data'] ?? null;

        return $data ? array_intersect_key($data, array_flip(['started_at', 'finished_at', 'status', 'counts'])) : null;
    }
}
