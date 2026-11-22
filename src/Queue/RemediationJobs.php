<?php
declare(strict_types=1);

namespace App\Queue;

use App\Audit\Store;
use App\Remediation\DashboardStatuses;
use App\Remediation\IndependentVerification;
use Doctrine\DBAL\ParameterType;

final class RemediationJobs
{
    private const PAGE_SIZE = 50;
    private const STATES = ['queued', 'running', 'failed', 'interrupted'];
    private const WORK = ['prepare', 'independent'];

    public function __construct(private readonly Store $store)
    {
    }

    public function list(string $state, string $work, int $page, int $now, string $attempt = '', string $selection = ''): array
    {
        $state = in_array($state, self::STATES, true) ? $state : '';
        $work = in_array($work, self::WORK, true) ? $work : '';
        $attempt = strtolower(trim($attempt));
        $attempt = preg_match('/^[a-f0-9]{24}$/D', $attempt) ? $attempt : '';
        $page = max(1, min(100000, $page));
        $limit = self::PAGE_SIZE + 1;
        $offset = ($page - 1) * self::PAGE_SIZE;
        $filters = [];
        $jobParams = ['now' => $now, 'prefix' => IndependentVerification::SETTINGS_PREFIX];
        $params = $jobParams;
        if ('' !== $state) {
            $filters[] = 'state = :state';
            $params['state'] = $state;
        }
        if ('' !== $work) {
            $filters[] = 'work = :work';
            $params['work'] = $work;
        }
        if ('' !== $attempt) {
            $filters[] = 'id = :attempt';
            $params['attempt'] = $attempt;
        }
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $title = $this->store->jsonText('c.data', 'title');
        $finding = $this->store->jsonText('c.data', 'finding');
        $advisory = $this->store->jsonText($finding, 'advisory');
        $name = "COALESCE($title, $advisory, SUBSTR(c.id, 1, 8)) AS title";
        $active = implode("', '", DashboardStatuses::GROUPS['active']);
        $verificationState = $this->store->jsonText('j.data', 'state');
        $lease = $this->store->jsonText('j.data', 'lease_until');
        $updated = $this->store->jsonText('j.data', 'updated_at');
        $requestHash = $this->store->jsonText('j.data', 'patch_sha256');
        $candidateHash = $this->store->jsonText('c.data', 'patch_sha256');
        $jobQuery = "
                SELECT c.id, $name, c.strategy, 'prepare' AS work, c.status AS stage,
                    CASE WHEN c.status IN ('queued', 'failed') THEN c.status ELSE 'running' END AS state,
                    COALESCE((SELECT a.created_at FROM audit a WHERE a.change_id = c.id ORDER BY a.id DESC LIMIT 1), c.created_at) AS updated_at
                FROM changes c WHERE c.status IN ('$active', 'failed')
                UNION ALL
                SELECT c.id, $name, c.strategy, 'independent' AS work, CAST(NULL AS TEXT) AS stage,
                    CASE WHEN $verificationState = 'running' AND CAST($lease AS BIGINT) <= :now THEN 'interrupted'
                        ELSE $verificationState END AS state, $updated AS updated_at
                FROM changes c JOIN operator_settings j ON j.id = (:prefix || c.id)
                WHERE c.status = 'awaiting_approval' AND $requestHash = $candidateHash
                    AND $verificationState IN ('queued', 'running', 'failed')";
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT * FROM ($jobQuery) jobs$where
            ORDER BY CASE state WHEN 'interrupted' THEN 0 WHEN 'running' THEN 1 WHEN 'queued' THEN 2 ELSE 3 END,
                CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END,
                CASE WHEN state = 'queued' THEN updated_at END ASC, updated_at DESC, id, work
            LIMIT $limit OFFSET $offset",
            $params,
            ['now' => ParameterType::INTEGER],
        );

        $followUp = null;
        if (preg_match('~^(prepare|independent)/([a-f0-9]{24})$~D', $selection, $selected)
            && [] === array_filter($rows, static fn (array $row): bool => $row['work'] === $selected[1] && $row['id'] === $selected[2])) {
            // A live job hidden by filters can still be found through the exact Queue lookup.
            $event = 'independent' === $selected[1]
                ? "(SELECT MAX(a.id) FROM audit a WHERE a.change_id = c.id AND a.kind = 'independent')" : 'NULL';
            $recorded = $this->store->db->fetchAssociative(
                "SELECT $name, $event AS event_id FROM changes c WHERE c.id = :selectedAttempt
                    AND NOT EXISTS (SELECT 1 FROM ($jobQuery) jobs WHERE jobs.id = c.id AND jobs.work = :selectedWork)",
                $jobParams + ['selectedAttempt' => $selected[2], 'selectedWork' => $selected[1]],
                ['now' => ParameterType::INTEGER],
            );
            if (false !== $recorded) {
                $followUp = ['selection' => $selection, 'title' => (string) $recorded['title'], 'eventId' => $recorded['event_id']];
            }
        }

        return [
            'rows' => array_slice($rows, 0, self::PAGE_SIZE), 'next' => count($rows) > self::PAGE_SIZE,
            'state' => $state, 'work' => $work, 'page' => $page, 'attempt' => $attempt, 'followUp' => $followUp,
        ];
    }
}
