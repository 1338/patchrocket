<?php
declare(strict_types=1);

namespace App\Fleet;

use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Remediation\Changes;
use App\Remediation\DockerRollout;
use Symfony\Component\Process\Process;

final class RolloutSchedules
{
    public function __construct(
        private readonly Store $store,
        private readonly Changes $changes,
        private readonly DockerRollout $rollout,
        private readonly Infrastructure $infra,
    ) {
    }

    public function add(string $id, string $previous, string $replacement, \DateTimeImmutable $after, ?string $canary): void
    {
        $change = $this->changes->get($id);
        if ('monitoring' !== $change?->getStatus()) {
            throw new \DomainException('Schedule an approved change with a scanned and staged replacement.');
        }
        if ($canary && ($canary === $id || 'standalone-binary' === $this->changes->get($canary)?->strategy
            || (!$this->store->row('SELECT id FROM rollout_schedules WHERE id = ?', [$canary])
            && 'deployed' !== $this->changes->get($canary)?->getStatus()))) {
            throw new \DomainException('Choose a scheduled or verified canary.');
        }
        $old = $this->infra->inspectContainer($previous);
        $new = $this->infra->inspectContainer($replacement);
        if (!$old['service'] || $old['service'] !== $new['service'] || $new['image'] !== $change->data['candidate_image']
            || $old['id'] === $new['id'] || $old['image'] === $new['image']) {
            throw new \DomainException('Choose distinct matching service containers with the staged replacement digest.');
        }
        $data = [
            'previous' => $old['id'], 'replacement' => $new['id'], 'canary' => $canary,
            'context' => $this->context(), 'service' => $old['service'],
        ];
        $inserted = $this->store->db->executeStatement(
            'INSERT INTO rollout_schedules (id, not_before, lease_until, status, data) VALUES (?, ?, 0, ?, ?) ON CONFLICT (id) DO NOTHING',
            [$id, $after->getTimestamp(), 'scheduled', Store::json($data)],
        );
        if (!$inserted) {
            throw new \DomainException('This change already has a rollout schedule.');
        }
    }

    public function cancel(string $id): void
    {
        $matched = $this->store->db->executeStatement(
            "UPDATE rollout_schedules SET status = 'canceled' WHERE id = ? AND status = 'scheduled' AND lease_until = 0",
            [$id],
        );
        if (!$matched) {
            throw new \DomainException('Only a scheduled, unclaimed rollout can be canceled.');
        }
    }

    public function all(): array
    {
        return $this->store->rows('SELECT * FROM rollout_schedules ORDER BY not_before, id');
    }

    public function runDue(): array
    {
        $context = $this->context();
        $now = time();
        $rows = $this->store->rows(
            "SELECT * FROM rollout_schedules WHERE status = 'scheduled' AND not_before <= ? AND lease_until <= ? ORDER BY not_before, id",
            [$now, $now],
        );
        $results = [];
        foreach ($rows as $row) {
            $id = $row['id'];
            $data = $row['data'];
            if ($context !== $data['context'] || ($data['canary'] && 'deployed' !== $this->changes->get($data['canary'])?->getStatus())) {
                continue;
            }
            $claimed = $this->store->db->executeStatement(
                "UPDATE rollout_schedules SET lease_until = ? WHERE id = ? AND status = 'scheduled' AND lease_until <= ?",
                [$lease = time() + 300, $id, time()],
            );
            if (!$claimed) {
                continue;
            }
            $status = 'failed';
            try {
                $change = $this->changes->get($id);
                if ($change && 'deployed' === $change->getStatus()) {
                    $completed = $change->data['rollout'] ?? [];
                    if (($completed['previous'] ?? null) === $data['previous'] && ($completed['replacement'] ?? null) === $data['replacement']) {
                        $status = 'deployed';
                    } else {
                        $data['last_error'] = 'The change was verified on a different runtime target.';
                    }
                } elseif ($change && $this->rollout->deploy($change, $data['previous'], $data['replacement'])) {
                    $status = 'deployed';
                }
            } catch (\DomainException $error) {
                $data['last_error'] = $error->getMessage();
            } catch (\Exception) {
                $data['last_error'] = 'The rollout was interrupted. Check the Docker service and change status.';
            }
            $this->store->db->update('rollout_schedules', ['status' => $status, 'lease_until' => 0, 'data' => Store::json($data)], ['id' => $id, 'lease_until' => $lease]);
            $results[$id] = $status;
            if ('failed' === $status || count($results) >= 5) {
                break;
            }
        }

        return $results;
    }

    private function context(): string
    {
        return trim((new Process(['docker', 'context', 'show'], timeout: 10))->mustRun()->getOutput());
    }
}
