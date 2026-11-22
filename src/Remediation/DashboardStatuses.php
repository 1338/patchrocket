<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;

final class DashboardStatuses
{
    public const GROUPS = [
        'active' => ['queued', 'patching', 'verifying', 'adapting'],
        'verified' => ['awaiting_approval', 'approved', 'monitoring', 'deployed', 'release_verified', 'binary_approved', 'binary_deployed'],
        'deployment_verified' => ['deployed', 'release_verified', 'binary_deployed'],
    ];

    public function __construct(private readonly Store $store, private readonly ApprovalPolicy $approval)
    {
    }

    public function withApprovalHolds(array $rows): array
    {
        $pending = array_column(array_filter($rows, static fn (array $row): bool => 'awaiting_approval' === $row['status']), 'id');
        $holds = $this->approval->pendingHolds($pending);
        foreach ($rows as $index => $row) {
            if (isset($holds[$row['id']])) {
                $rows[$index]['approval_hold'] = $holds[$row['id']]['reason'];
            }
        }

        return $rows;
    }

    public function query(string $columns = 'c.*'): string
    {
        $result = $this->store->jsonText('r.data', 'result');
        $releaseStatus = $this->store->jsonText($result, 'status');

        return "SELECT $columns, CASE
            WHEN c.strategy = 'standalone-binary' AND c.status IN ('approved', 'deployed') THEN 'binary_' || c.status
            WHEN c.status = 'approved' AND $releaseStatus = 'verified' THEN 'release_verified'
            ELSE c.status END AS display_status
            FROM changes c LEFT JOIN release_tracking r ON r.id = c.id";
    }

    public function reviewQuery(): string
    {
        $title = $this->store->jsonText('c.data', 'title');
        $finding = $this->store->jsonText('c.data', 'finding');
        $advisory = $this->store->jsonText($finding, 'advisory');
        $retryOf = $this->store->jsonText('c.data', 'retry_of');
        $executableId = $this->store->jsonText($this->store->jsonText('c.data', 'plan'), 'binary');

        return $this->query("c.id, c.status, c.strategy, c.created_at, COALESCE($title, $advisory, SUBSTR(c.id, 1, 8)) AS title,
            $advisory AS advisory, a.name AS asset_name, previous.id AS retry_of, $executableId AS executable_id,
            CASE
                WHEN c.status = 'failed' THEN 'execution-timeline'
                WHEN c.status = 'awaiting_approval' THEN 'approval'
                WHEN r.id IS NOT NULL THEN 'release-tracking'
                WHEN c.strategy = 'standalone-binary' AND c.status IN ('approved', 'deployed') THEN 'binary-installation'
                WHEN c.strategy = 'iac-image' AND c.status IN ('approved', 'deployed') THEN 'runtime-verification'
            END AS review_section")." LEFT JOIN assets a ON a.id = c.asset_id
            LEFT JOIN changes previous ON previous.id = $retryOf AND previous.id <> c.id AND previous.status = 'failed'
                AND previous.asset_id = c.asset_id AND previous.strategy = c.strategy";
    }
}
