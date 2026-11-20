<?php
declare(strict_types=1);

namespace App\Intelligence;

use App\Asset\Inventory;
use App\Audit\Store;

final class ScanSchedules
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly AssetScans $scans,
    ) {
    }

    public function add(string $asset, int $minutes): void
    {
        if ($minutes < 5 || $minutes > 43200) {
            throw new \InvalidArgumentException('Choose an interval between 5 minutes and 30 days.');
        }
        if (!in_array($this->inventory->get($asset)['kind'] ?? null, ['image', 'repository'], true)) {
            throw new \InvalidArgumentException('Choose a registered image or repository.');
        }
        $updated = $this->store->db->executeStatement(
            'INSERT INTO scan_schedules (id, next_at, lease_until, interval_seconds, data) VALUES (?, ?, 0, ?, ?)
             ON CONFLICT (id) DO UPDATE SET interval_seconds = excluded.interval_seconds WHERE scan_schedules.lease_until <= ?',
            [$asset, time(), $minutes * 60, '{}', time()],
        );
        if (0 === $updated) {
            throw new \DomainException('This scan is running.');
        }
    }

    public function remove(string $asset): void
    {
        $removed = $this->store->db->executeStatement('DELETE FROM scan_schedules WHERE id = ? AND lease_until <= ?', [$asset, time()]);
        if (!$removed && $this->store->row('SELECT id FROM scan_schedules WHERE id = ?', [$asset])) {
            throw new \DomainException('This scan is running.');
        }
    }

    public function all(): array
    {
        return $this->store->rows('SELECT s.*, a.name FROM scan_schedules s JOIN assets a ON a.id = s.id ORDER BY s.next_at, s.id');
    }

    public function runDue(int $limit): array
    {
        if ($limit < 1 || $limit > 50) {
            throw new \InvalidArgumentException('Choose a scan limit from 1 to 50.');
        }
        $now = time();
        $due = $this->store->rows(
            'SELECT * FROM scan_schedules WHERE next_at <= ? AND lease_until <= ? ORDER BY next_at, id LIMIT '.$limit,
            [$now, $now],
        );
        $results = [];
        foreach ($due as $schedule) {
            $id = $schedule['id'];
            $claimed = $this->store->db->executeStatement(
                'UPDATE scan_schedules SET lease_until = ? WHERE id = ? AND next_at <= ? AND lease_until <= ?',
                [$lease = time() + 1800, $id, $now, time()],
            );
            if (!$claimed) {
                continue;
            }
            $data = ['attempted_at' => gmdate(DATE_ATOM)];
            try {
                $data['findings'] = $this->scans->scan($id);
                $data['outcome'] = 'passed';
            } catch (\Exception) {
                $data['outcome'] = 'failed';
            }
            $this->store->db->update('scan_schedules', [
                'lease_until' => 0, 'next_at' => time() + (int) $schedule['interval_seconds'], 'data' => Store::json($data),
            ], ['id' => $id, 'lease_until' => $lease]);
            $results[$id] = $data['outcome'];
        }

        return $results;
    }
}
