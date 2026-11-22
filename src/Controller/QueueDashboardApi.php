<?php
declare(strict_types=1);

namespace App\Controller;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Intelligence\ScanSchedules;
use App\Queue\RemediationJobs;
use App\Queue\SchedulerActivity;
use App\Queue\TransportBacklog;
use App\Queue\WorkerPresence;
use App\Remediation\ReleaseTracking;
use App\Remediation\VmPackages;
use App\Settings\Connections;
use Doctrine\DBAL\ParameterType;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class QueueDashboardApi
{
    private const RELEASE_STATES = ['blocked', 'due', 'running', 'scheduled', 'paused', 'complete'];
    private const RELEASE_PAGE_SIZE = 50;
    private const SCAN_PAGE_SIZE = 50;
    private const SCAN_STATES = ['due', 'running', 'queued', 'scheduled'];
    private const SCAN_TARGETS = ['asset', 'connection'];
    private const SCAN_RESULTS = ['failed', 'successful', 'unrecorded'];
    private const CHECK_STATES = ['queued', 'running', 'complete', 'passed', 'failed'];
    private const CHECK_PAGE_SIZE = 50;

    public function __construct(private readonly Store $store)
    {
    }

    #[Route('/api/queue', name: 'api_queue', methods: ['GET'])]
    public function __invoke(
        Request $request,
        ReleaseTracking $tracking,
        ScanSchedules $scans,
        SchedulerActivity $activity,
        TransportBacklog $backlog,
        WorkerPresence $presence,
        Connections $inventoryConnections,
        RemediationJobs $jobs,
        VmPackages $vmPackages,
        CsrfTokenManagerInterface $tokens,
    ): JsonResponse {
        $now = time();
        $queues = [
            'patches' => ['name' => 'Inventory, scans and remediation', 'transport' => 'jobs'],
            'kubernetes_checks' => ['name' => 'Connection checks', 'transport' => 'kubernetes_checks'],
            'failed' => ['name' => 'Failed messages', 'transport' => null],
        ];
        $counts = $backlog->snapshot($now);
        $recentCounts = $presence->recentCounts($now);
        foreach ($queues as $key => &$queue) {
            $queue['total'] = $counts[$key]['total'] ?? 0;
            if (null !== $queue['transport']) {
                $queue += $counts[$key] ?? TransportBacklog::EMPTY_QUEUE;
                $queue['recent_workers'] = $recentCounts[$queue['transport']] ?? 0;
            }
        }
        unset($queue);
        $workerTransport = $request->query->getString('worker_transport');
        $workerTransport = in_array($workerTransport, array_column($queues, 'transport'), true) ? $workerTransport : '';
        $workerPage = max(1, min(100000, $request->query->getInt('worker_page', 1)));
        ['rows' => $workers, 'next' => $workerNext] = $presence->dashboardPage($now, $workerTransport, $workerPage);

        $admin = 'admin' === $request->attributes->get('_dashboard_role');
        $inventoryJobs = $inventoryConnections->inventoryJobs(
            $now,
            $request->query->getString('inventory_state'),
            $request->query->getString('inventory_operation'),
            $request->query->getString('inventory_q'),
            $request->query->getString('inventory_connection'),
            $request->query->getInt('inventory_page', 1),
            $admin,
        );
        $checkList = $this->connectionChecks($request, $now,
            $admin ? $request->attributes->getString('_dashboard_actor') : '');

        $releaseTrackers = $this->releaseTrackers($request, $now) + ['poller' => $tracking->pollSummary($now)];
        $scanScheduler = $scans->dueBacklog($now) + ['latest' => $activity->latest(SchedulerActivity::SCANS)];
        $connectionScans = $inventoryConnections->scheduledScans($now, includeRows: false);
        $scanSchedules = $this->scanSchedules($request, $now, $admin, $inventoryConnections);
        $remediationJobs = $jobs->list(
            $request->query->getString('job_state'), $request->query->getString('job_work'),
            $request->query->getInt('job_page', 1), $now, $request->query->getString('job_attempt'),
            $request->query->getString('job_selection'),
        );

        $data = compact('queues', 'workers', 'workerTransport', 'workerPage', 'workerNext', 'scanSchedules',
            'releaseTrackers', 'scanScheduler', 'connectionScans', 'remediationJobs')
            + $checkList + ['workerRecentSeconds' => WorkerPresence::RECENT_SECONDS,
                'connections' => $inventoryJobs['rows'], 'inventoryStates' => $inventoryJobs['states'], 'inventoryState' => $inventoryJobs['state'],
                'inventoryOperations' => $inventoryJobs['operations'], 'inventoryOperation' => $inventoryJobs['operation'],
                'inventorySearch' => $inventoryJobs['search'], 'inventoryConnection' => $inventoryJobs['connection'],
                'inventoryPage' => $inventoryJobs['page'], 'inventoryNext' => $inventoryJobs['next'],
                'inventoryOverdue' => $inventoryJobs['overdue_count']];
        if ($admin) {
            $data['vmPackageJobs'] = $vmPackages->queue(
                $request->query->getString('vm_state'), $request->query->getInt('vm_page', 1), $now, $request->query->getString('vm_asset'),
            );
        }

        $version = hash('sha256', Store::json([
            $request->attributes->getString('_dashboard_role'), $request->attributes->getString('_dashboard_actor'), $data,
        ]));
        $snapshot = ['unchanged' => true];
        if ($version !== $request->query->getString('known')) {
            $snapshot = $data + ['canManageSettings' => $admin, 'csrf' => $admin ? [
                'run' => $tokens->getToken('settings-run')->getValue(),
                'scan-retry' => $tokens->getToken('settings-scan-retry')->getValue(),
            ] : null];
        }

        return new JsonResponse($snapshot + compact('now', 'version'), headers: ['Cache-Control' => 'private, no-store']);
    }

    private function connectionChecks(Request $request, int $now, string $actor): array
    {
        $checkId = $request->query->getString('check_id');
        $checkId = preg_match('/^[a-f0-9]{32}$/D', $checkId) ? $checkId : '';
        $checkState = $request->query->getString('check_state');
        $checkState = '' === $checkId && in_array($checkState, self::CHECK_STATES, true) ? $checkState : '';
        $checkPage = '' === $checkId ? max(1, min(100000, $request->query->getInt('check_page', 1))) : 1;
        $limit = self::CHECK_PAGE_SIZE + 1;
        $offset = ($checkPage - 1) * self::CHECK_PAGE_SIZE;

        $target = $this->store->jsonText($this->store->jsonText('data', 'input'), 'target');
        $action = $this->store->jsonText('data', 'action');
        $expires = $this->store->jsonText('data', 'expires');
        $queued = $this->store->jsonText('data', 'queued_at');
        $checked = $this->store->jsonText('data', 'checked_at');
        $status = $this->store->jsonText('data', 'status');
        $result = $this->store->jsonText('data', 'result');
        $passed = $this->store->jsonText($result, 'passed');
        $outcome = "CASE WHEN $status = 'complete' AND $passed IN ('0', 'false') THEN 'failed'
                         WHEN $status = 'complete' AND $passed IN ('1', 'true') THEN 'passed' ELSE $status END";
        $diagnostic = 'NULL';
        $params = [];
        if ('' !== $actor) {
            $owner = $this->store->jsonText('data', 'actor');
            $error = $this->store->jsonText($result, 'error');
            $message = $this->store->jsonText($result, 'message');
            $diagnostic = "CASE WHEN $owner = ? AND $outcome = 'failed' THEN COALESCE($error, $message) END";
            $params[] = $actor;
        }
        $params[] = $now;
        $where = '';
        if ('' !== $checkId) {
            $where = 'WHERE id = ?';
            $params[] = 'kube-check:'.$checkId;
        } elseif ('' !== $checkState) {
            $where = 'WHERE outcome = ?';
            $params[] = $checkState;
        }

        $checks = $this->store->db->fetchAllAssociative(
            "SELECT id, target, action, status, outcome, queued_at, checked_at, diagnostic FROM (
                SELECT id, $target AS target, $action AS action, $status AS status, $outcome AS outcome,
                    $queued AS queued_at, $checked AS checked_at, $diagnostic AS diagnostic, CAST($expires AS BIGINT) AS expires_at
                FROM operator_settings WHERE id LIKE 'kube-check:%' AND CAST($expires AS BIGINT) > ?
            ) checks $where
            ORDER BY CASE outcome WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END, expires_at DESC, id
            LIMIT $limit OFFSET $offset", $params,
        );
        $checkNext = count($checks) > self::CHECK_PAGE_SIZE;
        $checks = array_slice($checks, 0, self::CHECK_PAGE_SIZE);
        foreach ($checks as &$check) {
            if ('repository' === $check['action'] && !str_starts_with($check['target'] ?? '', '/')) {
                $check['target'] = Repository::safeUrl($check['target']);
            }
        }
        unset($check);

        return compact('checks', 'checkId', 'checkPage', 'checkNext', 'checkState');
    }

    private function scanSchedules(Request $request, int $now, bool $admin, Connections $connections): array
    {
        $state = $request->query->getString('scan_state');
        $state = in_array($state, self::SCAN_STATES, true) ? $state : '';
        $target = $request->query->getString('scan_target');
        $target = in_array($target, self::SCAN_TARGETS, true) ? $target : '';
        $result = $request->query->getString('scan_result');
        $result = in_array($result, self::SCAN_RESULTS, true) ? $result : '';
        $search = trim($request->query->getString('scan_q'));
        $searchId = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/iD', $search) ? strtolower($search) : null;
        $page = max(1, min(100000, $request->query->getInt('scan_page', 1)));
        $limit = self::SCAN_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::SCAN_PAGE_SIZE;

        $filters = [];
        $params = ['scan_now' => $now];
        if ('' !== $state) {
            $filters[] = 'state = :state';
            $params['state'] = $state;
        }
        if ('' !== $target) {
            $filters[] = 'target_type = :target';
            $params['target'] = $target;
        }
        if (null !== $searchId) {
            $filters[] = 'id = :scan_id';
            $params['scan_id'] = $searchId;
        } elseif ('' !== $search) {
            $filters[] = "LOWER(name) LIKE LOWER(:scan_name) ESCAPE '!'";
            $params['scan_name'] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }
        $outcomeFilter = match ($result) {
            'failed' => "outcome = 'failed'",
            'successful' => "outcome IN ('complete', 'passed')",
            'unrecorded' => 'outcome IS NULL',
            default => null,
        };
        if ($outcomeFilter) {
            $filters[] = $outcomeFilter;
        }
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';

        $outcome = $this->store->jsonText('s.data', 'outcome');
        $attempted = $this->store->jsonText('s.data', 'attempted_at');
        $failureReason = $admin ? $this->store->jsonText('s.data', 'failure_reason') : 'NULL';
        $connectionQuery = $connections->scheduledScanQuery($admin);
        $assetState = DashboardScanEvidence::scheduleStateSql(':scan_now');
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT * FROM (
                SELECT s.id, a.name, a.kind, s.next_at, CAST(NULL AS TEXT) AS operation,
                    $outcome AS outcome, $attempted AS checked_at, $failureReason AS failure_reason, 0 AS has_failed_images,
                    CAST(NULL AS BIGINT) AS queued_at, $assetState AS state,
                    'asset' AS target_type
                FROM scan_schedules s JOIN assets a ON a.id = s.id
                UNION ALL
                SELECT connection.*, 'connection' AS target_type FROM ($connectionQuery) connection
             ) schedules$where
             ORDER BY CASE state WHEN 'due' THEN 0 WHEN 'running' THEN 1 WHEN 'queued' THEN 2 ELSE 3 END,
                 CASE WHEN next_at IS NULL THEN 1 ELSE 0 END, next_at, id, target_type
             LIMIT $limit OFFSET $offset",
            $params,
            ['scan_now' => ParameterType::INTEGER],
        );
        $next = count($rows) > self::SCAN_PAGE_SIZE;
        $rows = array_map(static fn (array $row): array => array_replace($row, ['has_failed_images' => (bool) $row['has_failed_images']]),
            array_slice($rows, 0, self::SCAN_PAGE_SIZE));

        return compact('rows', 'page', 'next', 'state', 'target', 'result', 'search', 'searchId');
    }

    private function releaseTrackers(Request $request, int $now): array
    {
        $state = $request->query->getString('release_state');
        $state = in_array($state, self::RELEASE_STATES, true) ? $state : '';
        $search = trim($request->query->getString('release_q'));
        $page = max(1, min(100000, $request->query->getInt('release_page', 1)));
        $offset = ($page - 1) * self::RELEASE_PAGE_SIZE;
        $limit = self::RELEASE_PAGE_SIZE + 1;

        $title = $this->store->jsonText('c.data', 'title');
        $finding = $this->store->jsonText('c.data', 'finding');
        $advisory = sprintf('COALESCE(%s, %s)', $this->store->jsonText($finding, 'advisory'), $this->store->jsonText('f.data', 'advisory'));
        $result = $this->store->jsonText('r.data', 'result');
        $status = $this->store->jsonText($result, 'status');
        $stage = $this->store->jsonText($result, 'stage');
        $checked = $this->store->jsonText($result, 'checked_at');
        $note = $this->store->jsonText($result, 'note');

        $filters = [];
        $params = [$now, $now, ...ReleaseTracking::TERMINAL_STATUSES];
        if ('' !== $state) {
            $filters[] = 'blocked' === $state ? 'last_status = ?' : 'poll_state = ?';
            $params[] = $state;
        }
        if (preg_match('/^[a-f0-9]{24}$/iD', $search)) {
            $filters[] = 'id = ?';
            $params[] = strtolower($search);
        } elseif ('' !== $search) {
            $matches = ["LOWER(title) LIKE LOWER(?) ESCAPE '!'",
                "LOWER(advisory) LIKE LOWER(?) ESCAPE '!'", "LOWER(stage) LIKE LOWER(?) ESCAPE '!'"];
            $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            array_push($params, $pattern, $pattern, $pattern);
            if (preg_match('/^[a-f0-9]{8,23}$/iD', $search)) {
                $matches[] = 'id LIKE ?';
                $params[] = strtolower($search).'%';
            }
            $filters[] = '('.implode(' OR ', $matches).')';
        }
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT * FROM (
                SELECT r.id, COALESCE($title, $advisory, SUBSTR(c.id, 1, 8)) AS title, $advisory AS advisory, r.next_at,
                    $status AS last_status, $stage AS stage, $checked AS checked_at,
                    CASE WHEN $status IN ('blocked', 'waiting', 'closed') THEN $note END AS note,
                    CASE WHEN r.lease_until > ? THEN 'running'
                         WHEN r.next_at > 0 AND r.next_at <= ? THEN 'due'
                         WHEN r.next_at > 0 THEN 'scheduled'
                         WHEN $status IN (?, ?) THEN 'complete'
                         ELSE 'paused' END AS poll_state
                FROM release_tracking r JOIN changes c ON c.id = r.id
                LEFT JOIN findings f ON f.id = c.finding_id
             ) trackers$where
             ORDER BY CASE WHEN poll_state = 'due' THEN 0 WHEN last_status = 'blocked' THEN 1
                           WHEN poll_state = 'running' THEN 2 WHEN poll_state = 'scheduled' THEN 3 ELSE 4 END,
                      CASE WHEN poll_state IN ('due', 'scheduled') THEN next_at ELSE 0 END,
                      COALESCE(checked_at, '') DESC, id
             LIMIT $limit OFFSET $offset",
            $params,
        );

        return ['rows' => array_slice($rows, 0, self::RELEASE_PAGE_SIZE), 'state' => $state, 'states' => self::RELEASE_STATES, 'search' => $search,
            'page' => $page, 'next' => count($rows) > self::RELEASE_PAGE_SIZE];
    }
}
