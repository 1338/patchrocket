<?php
declare(strict_types=1);

namespace App\Intelligence;

use App\Asset\Inventory;
use App\Audit\Store;
use Symfony\Component\Process\Exception\ProcessTimedOutException;

final class ScanSchedules
{
    private const DUE = 'next_at <= ? AND lease_until <= ?';
    private const SETTINGS_PAGE_SIZE = 25;

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

    public function requestRetry(string $asset): bool
    {
        $now = time();
        $outcome = $this->store->jsonText('data', 'outcome');
        $updated = $this->store->db->executeStatement(
            "UPDATE scan_schedules SET next_at = ? WHERE id = ? AND next_at > ? AND lease_until <= ? AND $outcome = 'failed'",
            [$now, $asset, $now, $now],
        );
        if ($updated) {
            return true;
        }
        $schedule = $this->store->row('SELECT * FROM scan_schedules WHERE id = ?', [$asset]);
        if (!$schedule) {
            throw new \DomainException('This asset no longer has a scan schedule.');
        }
        $checkedAt = time();
        if ($schedule['lease_until'] > $checkedAt) {
            throw new \DomainException('This scan is already running.');
        }
        if ('failed' !== ($schedule['data']['outcome'] ?? null)) {
            throw new \DomainException('The latest scheduled scan does not need a retry.');
        }
        if ($schedule['next_at'] > $checkedAt) {
            throw new \DomainException('The scan schedule changed. Refresh and try again.');
        }

        return false;
    }

    public function all(): array
    {
        return $this->store->rows('SELECT s.*, a.name FROM scan_schedules s JOIN assets a ON a.id = s.id ORDER BY s.next_at, s.id');
    }

    public function settingsPage(string $search, int $page, bool $scheduled): array
    {
        $filters = [$scheduled ? 's.id IS NOT NULL' : "s.id IS NULL AND a.kind IN ('image', 'repository')"];
        $params = [];
        if (preg_match('/^[a-f0-9]{64}$/iD', $search)) {
            $filters[] = 'a.id = ?';
            $params[] = strtolower($search);
        } elseif ('' !== $search) {
            $filters[] = "LOWER(a.name) LIKE LOWER(?) ESCAPE '!'";
            $params[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }
        $where = implode(' AND ', $filters);
        $order = $scheduled ? 's.next_at, a.id' : 'LOWER(a.name), a.kind, a.id';
        $limit = self::SETTINGS_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::SETTINGS_PAGE_SIZE;
        $columns = $scheduled ? 'a.id, a.name, a.kind, s.interval_seconds, s.next_at, s.lease_until, s.data' : 'a.id, a.name, a.kind';
        $rows = $this->store->rows("SELECT $columns FROM assets a LEFT JOIN scan_schedules s ON s.id = a.id
            WHERE $where ORDER BY $order LIMIT $limit OFFSET $offset", $params);

        return ['rows' => array_slice($rows, 0, self::SETTINGS_PAGE_SIZE), 'page' => $page, 'search' => $search,
            'next' => count($rows) > self::SETTINGS_PAGE_SIZE];
    }

    public function settingsTarget(string $asset): ?array
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $asset)) {
            return null;
        }

        return $this->store->row("SELECT a.id, a.name, a.kind, s.interval_seconds, s.next_at, s.lease_until, s.data
            FROM assets a LEFT JOIN scan_schedules s ON s.id = a.id
            WHERE a.id = ? AND (s.id IS NOT NULL OR a.kind IN ('image', 'repository'))", [$asset]);
    }

    public function dueBacklog(int $now): array
    {
        $due = $this->store->db->fetchAssociative(
            'SELECT COUNT(*) AS total, MIN(next_at) AS oldest FROM scan_schedules s JOIN assets a ON a.id = s.id WHERE '.self::DUE,
            [$now, $now],
        );

        return ['due_count' => (int) $due['total'], 'oldest_due' => null !== $due['oldest'] ? (int) $due['oldest'] : null];
    }

    public function runDue(int $limit): array
    {
        if ($limit < 1 || $limit > 50) {
            throw new \InvalidArgumentException('Choose a scan limit from 1 to 50.');
        }
        $now = time();
        $due = $this->store->rows(
            'SELECT * FROM scan_schedules WHERE '.self::DUE.' ORDER BY next_at, id LIMIT '.$limit,
            [$now, $now],
        );
        $results = [];
        foreach ($due as $schedule) {
            $id = $schedule['id'];
            $claimed = $this->store->db->executeStatement(
                'UPDATE scan_schedules SET lease_until = ? WHERE id = ? AND '.self::DUE,
                [$lease = time() + 1800, $id, $now, time()],
            );
            if (!$claimed) {
                continue;
            }
            $data = ['attempted_at' => gmdate(DATE_ATOM)];
            try {
                $data['findings'] = $this->scans->scan($id);
                $data['outcome'] = 'passed';
            } catch (\Throwable $error) {
                $data['outcome'] = 'failed';
                $data['failure_reason'] = match (true) {
                    $error instanceof \DomainException => $error->getMessage(),
                    $error instanceof ProcessTimedOutException => 'The asset scan timed out. Check scanner performance and the timeout in Scanning Settings.',
                    'repository' === ($this->inventory->get($id)['kind'] ?? null)
                        => 'The scanner could not complete this repository scan. Check the checkout and scanner on the scheduler host.',
                    default => 'The scanner could not complete this image scan. Check the image digest, registry access, and scanner on the scheduler host.',
                };
            }
            $this->store->db->update('scan_schedules', [
                'lease_until' => 0, 'next_at' => time() + (int) $schedule['interval_seconds'], 'data' => Store::json($data),
            ], ['id' => $id, 'lease_until' => $lease]);
            $results[$id] = $data['outcome'];
        }

        return $results;
    }
}
