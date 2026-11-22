<?php
declare(strict_types=1);

namespace App\Settings;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\SecretManagers;
use Doctrine\DBAL\ParameterType;
use Symfony\Component\Messenger\MessageBusInterface;

final class Connections
{
    public const DISCOVERY_PAGE_SIZE = 10;
    public const DISCOVERY_RESULTS = ['failed', 'complete', 'unrecorded'];
    public const DISCOVERY_JOB_STATES = ['queued', 'running', 'overdue'];
    private const ACTIVE_JOB_SECONDS = 3600;
    private const ACTIVE_JOB_STATES = ['queued', 'running'];
    private const JOB_STATES = [...self::ACTIVE_JOB_STATES, 'complete', 'failed'];
    private const JOB_OPERATIONS = ['discover', 'scan', 'argo', 'delivery'];
    private const JOB_PAGE_SIZE = 50;
    private const SETTINGS_PAGE_SIZE = 25;

    private const FIELDS = [
        'vm' => ['target', 'port', 'docker_inventory', 'docker_sudo', 'credential'],
        'cluster' => ['target', 'namespace', 'repository', 'all_namespaces', 'registries', 'platform', 'credential', 'host_asset', 'argo_namespace'],
        'docker' => ['target', 'repository', 'context'],
        'registry' => ['target', 'platform', 'repository'],
        'repository' => ['target', 'subdirectory', 'editable', 'credential', 'role', 'infra_context', 'canonical_url'],
    ];

    public function __construct(private readonly Store $store, private readonly MessageBusInterface $bus)
    {
    }

    public function all(): array
    {
        return $this->store->rows('SELECT * FROM inventory_connections ORDER BY kind, name, id');
    }

    public static function settingsKinds(): array
    {
        return array_keys(self::FIELDS);
    }

    public static function settingsJobStates(): array
    {
        return ['saved', ...self::JOB_STATES];
    }

    public static function hasInventoryJob(array $row): bool
    {
        return in_array($row['data']['status'] ?? null, self::JOB_STATES, true);
    }

    public function inventoryJobState(array $row): ?string
    {
        if (!self::hasInventoryJob($row)) {
            return null;
        }
        $status = $row['data']['status'];

        return in_array($status, self::ACTIVE_JOB_STATES, true) && !$this->active($row['data']) ? 'overdue' : $status;
    }

    public function settingsPage(string $search, string $kind, string $state, int $page): array
    {
        $filters = $params = [];
        if ('' !== $kind) {
            $filters[] = 'kind = ?';
            $params[] = $kind;
        }
        if ('' !== $state) {
            $jobState = $this->store->jsonText('data', 'status');
            $filters[] = "COALESCE(NULLIF($jobState, ''), 'saved') = ?";
            $params[] = $state;
        }
        if ('' !== $search) {
            [$filter, $value] = self::nameOrIdFilter($search);
            $searchValues = [$value];
            if ('repository' === $kind && str_contains($search, '/')) {
                $target = $this->store->jsonText('data', 'target');
                $canonical = $this->store->jsonText('data', 'canonical_url');
                $filter = "($filter OR LOWER($target) LIKE LOWER(?) ESCAPE '!' OR LOWER($canonical) LIKE LOWER(?) ESCAPE '!')";
                $searchValues = [$value, $value, $value];
            }
            $filters[] = $filter;
            array_push($params, ...$searchValues);
        }
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $limit = self::SETTINGS_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::SETTINGS_PAGE_SIZE;
        $rows = $this->store->rows("SELECT * FROM inventory_connections$where
            ORDER BY kind, LOWER(name), id LIMIT $limit OFFSET $offset", $params);

        return ['rows' => array_slice($rows, 0, self::SETTINGS_PAGE_SIZE), 'next' => count($rows) > self::SETTINGS_PAGE_SIZE];
    }

    private static function nameOrIdFilter(string $search, string $prefix = ''): array
    {
        return preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/iD', $search)
            ? [$prefix.'id = ?', strtolower($search)]
            : ["LOWER({$prefix}name) LIKE LOWER(?) ESCAPE '!'", '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%'];
    }

    public function byKind(string $kind): array
    {
        return $this->store->rows('SELECT * FROM inventory_connections WHERE kind = ? ORDER BY name, id', [$kind]);
    }

    public function directoryPage(string $kind, string $search, int $page, string $edit): array
    {
        if ('' === $edit) {
            return $this->settingsPage(trim($search), $kind, '', max(1, min(100000, $page))) + ['selected' => null];
        }
        $connection = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $edit) ? $this->get($edit) : null;

        return ['rows' => [], 'next' => false, 'selected' => $kind === ($connection['kind'] ?? null) ? $connection : null];
    }

    public function get(string $id): ?array
    {
        return $this->store->row('SELECT * FROM inventory_connections WHERE id = ?', [$id]);
    }

    public static function needsManagedCredential(array $connection): bool
    {
        $data = $connection['data'];
        $required = match ($connection['kind']) {
            'vm' => true,
            'cluster' => 'worker' !== ($data['credential_mode'] ?? 'managed'),
            'repository' => str_starts_with($data['target'] ?? '', 'https://'),
            default => false,
        };

        return $required && !SecretManagers::validReference($data['credential'] ?? '');
    }

    public function firstConnectionWithoutCredentialBlocker(): ?string
    {
        foreach ($this->store->iterate('SELECT id, kind, data FROM inventory_connections ORDER BY id') as $connection) {
            if (!self::needsManagedCredential($connection)) {
                return $connection['id'];
            }
        }

        return null;
    }

    public function discoveryChecklist(
        string $selected, string $search = '', int $limit = self::DISCOVERY_PAGE_SIZE, int $offset = 0,
        string $result = '', string $jobState = '', bool $credentialsNeeded = false,
    ): array
    {
        $now = time();
        $status = $this->store->jsonText('c.data', 'status');
        $queuedAt = $this->store->jsonText('c.data', 'queued_at');
        $lastDiscovery = $this->store->jsonText('c.data', 'last_discovery');
        $assetId = $this->store->jsonText($lastDiscovery, 'asset_id');
        $filters = $params = [];
        if ('' !== $search) {
            [$condition, $value] = self::nameOrIdFilter($search, 'c.');
            $filters[] = $condition;
            $params[] = $value;
        }
        if (in_array($result, self::DISCOVERY_RESULTS, true)) {
            $outcome = $this->discoveryResultSql($lastDiscovery, $status);
            if ('unrecorded' === $result) {
                $filters[] = "$outcome IS NULL";
            } else {
                $filters[] = "$outcome = ?";
                $params[] = $result;
            }
        }
        if (in_array($jobState, self::DISCOVERY_JOB_STATES, true)) {
            $overdue = self::overdueJobSql($status, $queuedAt);
            $filters[] = "CASE WHEN $overdue THEN 'overdue' ELSE $status END = ?";
            array_push($params, $now - self::ACTIVE_JOB_SECONDS, $jobState);
        }
        if ($credentialsNeeded) {
            $filters[] = "c.kind IN ('vm', 'cluster', 'repository')";
        }
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $params[] = $selected;
        // Apply the credential predicate before paging so it uses the same reference rules as discovery.
        $window = $credentialsNeeded ? '' : " LIMIT $limit OFFSET $offset";
        $rows = $this->store->iterate("SELECT c.id, c.kind, c.name, c.data, a.id AS discovery_asset
            FROM inventory_connections c LEFT JOIN assets a ON a.id = $assetId$where
            ORDER BY CASE WHEN c.id = ? THEN 0 ELSE 1 END, COALESCE(CAST($queuedAt AS BIGINT), 0) DESC, c.name, c.id$window", $params);

        $checklist = [];
        foreach ($rows as $row) {
            $needsCredential = self::needsManagedCredential($row);
            if ($credentialsNeeded) {
                if (!$needsCredential) {
                    continue;
                }
                if ($offset > 0) {
                    --$offset;
                    continue;
                }
            }
            if (count($checklist) >= $limit) {
                break;
            }
            $data = $row['data'];
            $discovery = self::lastDiscovery($data);
            if ($discovery) {
                $discovery = array_intersect_key($discovery, array_flip(['status', 'result', 'finished_at']));
                if ('complete' === ($discovery['status'] ?? null) && $row['discovery_asset']) {
                    $discovery['asset_id'] = $row['discovery_asset'];
                }
            }
            $lastScan = self::lastScan($data);
            $scan = null;
            if (in_array($lastScan['status'] ?? null, ['complete', 'failed'], true)) {
                $scan = array_intersect_key($lastScan, array_flip(['status', 'finished_at', 'failure_reason'])) + [
                    'has_failed_images' => 'cluster' === $row['kind'] && 'failed' === $lastScan['status'] && !empty($lastScan['failed_images']),
                ];
            }

            $checklist[] = [
                'id' => $row['id'], 'kind' => $row['kind'], 'name' => $row['name'],
                'busy' => $this->active($data, $now),
                'needs_credential' => $needsCredential,
                'has_job' => self::hasInventoryJob($row),
                'job' => array_intersect_key($data, array_flip(['status', 'operation'])),
                'discovery' => $discovery ?: null,
                'scan' => $scan,
                'scan_blocker' => self::checklistScanBlocker($row),
            ];
        }

        return $checklist;
    }

    private function discoveryResultSql(string $lastDiscovery, string $status): string
    {
        $recorded = $this->store->jsonText($lastDiscovery, 'status');
        $operation = $this->store->jsonText('c.data', 'operation');
        $legacyTime = $this->store->jsonText('c.data', 'last_discovery_at');

        return "CASE WHEN $lastDiscovery IS NOT NULL THEN $recorded
            WHEN $operation = 'discover' AND $status IN ('complete', 'failed') THEN $status
            WHEN $legacyTime NOT IN ('', '0') THEN 'complete' END";
    }

    public function hasActiveInventoryWork(string $search, ?string $operation = null): bool
    {
        $status = $this->store->jsonText('data', 'status');
        $queued = $this->store->jsonText('data', 'queued_at');
        $where = "$status IN ('queued', 'running') AND COALESCE(CAST($queued AS BIGINT), 0) > CAST(? AS BIGINT)";
        $params = [time() - self::ACTIVE_JOB_SECONDS];
        if (null !== $operation) {
            $where .= ' AND '.$this->store->jsonText('data', 'operation').' = ?';
            $params[] = $operation;
        }
        if ('' !== $search) {
            [$condition, $value] = self::nameOrIdFilter($search);
            $where .= ' AND '.$condition;
            $params[] = $value;
        }

        return false !== $this->store->db->fetchOne("SELECT 1 FROM inventory_connections WHERE $where LIMIT 1", $params);
    }

    public function discoveryNeedingAttention(int $now): ?array
    {
        $status = $this->store->jsonText('c.data', 'status');
        $queuedAt = $this->store->jsonText('c.data', 'queued_at');
        $operation = $this->store->jsonText('c.data', 'operation');
        $outcome = $this->discoveryResultSql($this->store->jsonText('c.data', 'last_discovery'), $status);
        $overdue = self::overdueJobSql($status, $queuedAt);
        $cutoff = $now - self::ACTIVE_JOB_SECONDS;

        return $this->store->db->fetchAssociative(
            "SELECT id, state FROM (
                SELECT c.id, COALESCE(CAST($queuedAt AS BIGINT), 0) AS queued_at,
                    CASE WHEN $operation = 'discover' AND $overdue THEN 'overdue'
                        WHEN (COALESCE($status, '') NOT IN ('queued', 'running') OR $overdue) AND $outcome = 'failed' THEN 'failed'
                    END AS state
                FROM inventory_connections c
            ) discovery_attention WHERE state IS NOT NULL
            ORDER BY CASE state WHEN 'overdue' THEN 0 ELSE 1 END, queued_at DESC, id LIMIT 1",
            [$cutoff, $cutoff],
        ) ?: null;
    }

    private static function overdueJobSql(string $status, string $queued): string
    {
        return "$status IN ('queued', 'running') AND COALESCE(CAST($queued AS BIGINT), 0) <= CAST(? AS BIGINT)";
    }

    public function inventoryJobs(int $now, string $state, string $operation, string $search, string $connection, int $page, bool $diagnostics): array
    {
        $states = [...self::JOB_STATES, 'overdue'];
        $state = in_array($state, $states, true) ? $state : '';
        $operation = in_array($operation, self::JOB_OPERATIONS, true) ? $operation : '';
        $search = trim($search);
        $connection = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $connection) ? $connection : '';
        $page = max(1, min(100000, $page));
        $offset = ($page - 1) * self::JOB_PAGE_SIZE;
        $limit = self::JOB_PAGE_SIZE + 1;
        $operations = self::JOB_OPERATIONS;

        $status = $this->store->jsonText('data', 'status');
        $queued = $this->store->jsonText('data', 'queued_at');
        $action = $this->store->jsonText('data', 'operation');
        $finished = $this->store->jsonText('data', 'finished_at');
        $result = $diagnostics ? $this->store->jsonText('data', 'result') : 'NULL';
        $failedImages = '0';
        if ($diagnostics) {
            $lastScan = $this->store->jsonText('data', 'last_scan');
            $attempted = $this->store->jsonText($lastScan, 'finished_at');
            $imageBatch = $this->recordedFailedImagesSql($lastScan);
            $failedImages = "CASE WHEN kind = 'cluster' AND $action = 'scan' AND $status = 'failed'
                AND $attempted = $finished AND $imageBatch THEN 1 ELSE 0 END";
        }
        $overdue = self::overdueJobSql($status, $queued);
        $cutoff = $now - self::ACTIVE_JOB_SECONDS;
        $overdueCount = (int) $this->store->db->fetchOne("SELECT COUNT(*) FROM inventory_connections WHERE $overdue", [$cutoff]);
        $filters = ["$status IN ('queued', 'running', 'complete', 'failed')"];
        $params = [$cutoff];
        foreach ([$action => $operation, 'id' => $connection] as $field => $value) {
            if ('' !== $value) {
                $filters[] = "$field = ?";
                $params[] = $value;
            }
        }
        if ('' !== $search) {
            $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            $filters[] = "(LOWER(name) LIKE LOWER(?) ESCAPE '!' OR id LIKE LOWER(?) ESCAPE '!')";
            array_push($params, $pattern, $pattern);
        }

        $where = implode(' AND ', $filters);
        $stateFilter = '' === $state ? '' : 'WHERE state = ?';
        if ('' !== $state) {
            $params[] = $state;
        }
        $expires = 'CAST('.$queued.' AS BIGINT) + '.self::ACTIVE_JOB_SECONDS;
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT * FROM (
                SELECT id, name, kind, $status AS status, $action AS action, $queued AS queued, $finished AS finished, $result AS result,
                    $failedImages AS has_failed_images,
                    CASE WHEN $overdue THEN 'overdue' ELSE $status END AS state, $expires AS expires_at
                FROM inventory_connections WHERE $where
            ) inventory_jobs $stateFilter
            ORDER BY CASE state WHEN 'running' THEN 0 WHEN 'queued' THEN 1 WHEN 'overdue' THEN 2 ELSE 3 END,
                COALESCE(CAST(queued AS BIGINT), 0) DESC, id LIMIT $limit OFFSET $offset",
            $params,
        );

        return compact('states', 'state', 'operations', 'operation', 'search', 'connection', 'page') + [
            'rows' => array_map(static fn (array $row): array => array_replace($row, ['has_failed_images' => (bool) $row['has_failed_images']]),
                array_slice($rows, 0, self::JOB_PAGE_SIZE)),
            'next' => count($rows) > self::JOB_PAGE_SIZE,
            'overdue_count' => $overdueCount,
        ];
    }

    public function save(string $kind, array $input, ?array $expectedData = null): string
    {
        $fields = self::FIELDS[$kind] ?? throw new \DomainException('Choose a connection type.');
        $id = $input['id'] ?? '';
        $existing = $id ? $this->get($id) : null;
        if ($id && (!$existing || $existing['kind'] !== $kind)) {
            throw new \DomainException('This connection does not exist.');
        }
        if (null !== $expectedData && $expectedData !== ($existing['data'] ?? null)) {
            throw new \DomainException('The connection changed during the edit. Reload Settings and try again.');
        }
        if ($existing && $this->active($existing['data'])) {
            throw new \DomainException('Wait for the inventory job to finish before editing the connection.');
        }
        $previous = $existing['data'] ?? [];
        $cluster = 'cluster' === $kind;
        $name = trim($input['name'] ?? '');
        $data = [];
        foreach ($fields as $field) {
            $value = trim($input[$field] ?? ($cluster ? ($previous[$field] ?? '') : ''));
            if (strlen($value) > 2000 || str_contains($value, "\0")) {
                throw new \DomainException('A connection field is too long or invalid.');
            }
            $data[$field] = $value;
        }
        if ('' === $name || strlen($name) > 120 || ('' === $data['target'] && 'docker' !== $kind)) {
            throw new \DomainException('Supply a name and connection target.');
        }
        $managed = 'vm' === $kind || ('repository' === $kind && str_starts_with($data['target'], 'https://'));
        if ($cluster) {
            $mode = $input['credential_mode'] ?? ($previous['credential_mode'] ?? 'managed');
            if (!in_array($mode, ['managed', 'worker'], true) || ('worker' === $mode && '' !== $data['credential'])) {
                throw new \DomainException('Choose either a worker kubeconfig or a managed credential reference.');
            }
            if (array_key_exists('credential_mode', $input)) {
                $data['credential_mode'] = $mode;
            }
            $managed = 'managed' === $mode;
        }
        if ($managed && !SecretManagers::validReference($data['credential'] ?? '')) {
            throw new \DomainException('Enter a managed credential reference in manager:secret format.');
        }
        if ('vm' === $kind && !self::validVmTarget($data['target'])) {
            throw new \DomainException('Enter the explicit SSH user and host, for example scanner@vm.example.');
        }
        if ('vm' === $kind && '' !== $data['port'] && false === filter_var($data['port'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]])) {
            throw new \DomainException('Enter an SSH port between 1 and 65535.');
        }
        $previousMinutes = filter_var($previous['interval'] ?? 0, FILTER_VALIDATE_INT);
        $minutes = filter_var($input['interval'] ?? ($previous['interval'] ?? 0), FILTER_VALIDATE_INT);
        if (false === $minutes || ($minutes !== 0 && ($minutes < 5 || $minutes > 43200))) {
            throw new \DomainException('Enter 0 for manual scans, or an interval between 5 minutes and 30 days.');
        }
        if (('docker' === $kind && $minutes) || ('cluster' === $kind && $minutes && !$data['registries'])) {
            throw new \DomainException('Scheduled cluster scans require an explicit registry list. Docker connection schedules use individual image assets.');
        }
        if ($cluster) {
            if (array_key_exists('argo_namespace', $input)) {
                $this->validateArgoNamespace($data['argo_namespace']);
            } else {
                unset($data['argo_namespace']);
            }
            $data = self::saveClusterScope($input, array_replace($previous, $data), $previous);
        }
        if ('repository' === $kind && $data['canonical_url'] && !Repository::identity($data['canonical_url'])) {
            throw new \DomainException('Enter a Git repository URL for matching Argo CD sources.');
        }
        if ('repository' === $kind && $data['canonical_url']) {
            $data['canonical_url'] = Repository::safeUrl($data['canonical_url']);
        }
        if ('vm' === $kind) {
            $data['package_updates'] = '1' === ($input['package_updates'] ?? '') ? '1' : '';
        }
        $data['interval'] = $minutes;
        $data['next_at'] = match (true) {
            0 === $minutes => 0,
            $minutes === $previousMinutes && isset($previous['next_at']) => $previous['next_at'],
            default => time() + $minutes * 60,
        };
        if ($existing) {
            if (!$cluster) {
                $data = array_replace($previous, $data);
            }
            $scanSettingsChanged = self::scanSettings($kind, $previous) !== self::scanSettings($kind, $data);
            $lastScan = self::lastScan($previous);
            if (null !== $lastScan) {
                // An empty result also suppresses the fallback to a legacy job for the previous configuration.
                $data['last_scan'] = $scanSettingsChanged ? [] : $lastScan;
            }
            $lastDiscovery = self::lastDiscovery($previous);
            if (null !== $lastDiscovery) {
                if (self::discoverySettings($kind, $previous) !== self::discoverySettings($kind, $data)) {
                    $data['last_discovery'] = [];
                    unset($data['last_discovery_at']);
                } else {
                    $data['last_discovery'] = $lastDiscovery;
                }
            }
            if ($scanSettingsChanged && in_array($previous['status'] ?? null, self::ACTIVE_JOB_STATES, true)) {
                unset($data['token']);
            }
            $updated = $this->store->db->update('inventory_connections', ['name' => $name, 'data' => Store::json($data)], [
                'id' => $id, 'data' => Store::json($existing['data']),
            ]);
            if (!$updated && $this->get($id)) {
                throw new \DomainException('The connection changed during the edit. Reload Settings and try again.');
            }
        } else {
            $id = bin2hex(random_bytes(16));
            $this->store->db->insert('inventory_connections', [
                'id' => $id, 'kind' => $kind, 'name' => $name, 'data' => Store::json($data),
            ]);
        }

        return $id;
    }

    /** @return list<string>|null Null means all namespaces. */
    public static function clusterNamespaces(array $data): ?array
    {
        $mode = $data['namespace_mode'] ?? null;
        if ('all' === $mode || (null === $mode && !empty($data['all_namespaces']))) {
            return null;
        }

        return $data['namespaces'] ?? [($data['namespace'] ?? '') ?: 'default'];
    }

    public static function coversNamespace(array $data, string $namespace): bool
    {
        $namespaces = self::clusterNamespaces($data);

        return null === $namespaces || in_array($namespace, $namespaces, true);
    }

    private static function saveClusterScope(array $input, array $data, array $previous): array
    {
        if (!array_key_exists('namespace_mode', $input) && !array_key_exists('namespaces', $input)) {
            // The legacy form sends the namespace text field even when the All checkbox is unchecked.
            if (array_key_exists('namespace', $input) && !array_key_exists('all_namespaces', $input)) {
                $data['all_namespaces'] = '';
            }
            if ((!empty($data['all_namespaces']) !== !empty($previous['all_namespaces']))
                || (($data['namespace'] ?: 'default') !== (($previous['namespace'] ?? '') ?: 'default'))) {
                unset($data['namespace_mode'], $data['namespaces']);
            } elseif (isset($previous['namespace_mode'])) {
                $data['namespace'] = $previous['namespace'];
                $data['all_namespaces'] = $previous['all_namespaces'];
            }

            return $data;
        }
        $mode = $input['namespace_mode'] ?? 'selected';
        if (!in_array($mode, ['all', 'selected'], true)) {
            throw new \DomainException('Choose all namespaces or selected namespaces.');
        }
        $namespaces = 'all' === $mode ? [] : ($input['namespaces'] ?? []);
        if ('selected' === $mode && (!is_array($namespaces) || !array_is_list($namespaces) || !$namespaces || count($namespaces) > 20)) {
            throw new \DomainException('Select between 1 and 20 Kubernetes namespaces.');
        }
        foreach ($namespaces as $namespace) {
            if (!is_string($namespace) || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
                throw new \DomainException('Enter valid Kubernetes namespace names.');
            }
        }
        $namespaces = array_values(array_unique($namespaces));
        sort($namespaces, SORT_STRING);

        return array_replace($data, [
            'namespace_mode' => $mode, 'namespaces' => $namespaces,
            'namespace' => $namespaces[0] ?? 'default', 'all_namespaces' => 'all' === $mode ? '1' : '',
        ]);
    }

    public function saveArgo(string $id, string $namespace, string $reference): void
    {
        $row = $this->get($id);
        if (($row['kind'] ?? null) !== 'cluster') {
            throw new \DomainException('Choose a Kubernetes cluster connection for Argo CD.');
        }
        $namespace = trim($namespace);
        $reference = trim($reference);
        $this->validateArgoNamespace($namespace);
        if ('' !== $reference && !SecretManagers::validReference($reference)) {
            throw new \DomainException('Enter an Argo CD credential reference in manager:secret format.');
        }
        if ($this->active($row['data']) || !$this->update($row, array_replace($row['data'], [
            'argo_namespace' => $namespace, 'argo_credential' => $reference,
        ]))) {
            throw new \DomainException('Wait for the inventory job to finish, then refresh and try again.');
        }
    }

    public static function argoCredential(array $data): string
    {
        return ($data['argo_credential'] ?? '') ?: ($data['credential'] ?? '');
    }

    private function validateArgoNamespace(string $namespace): void
    {
        if ('' !== $namespace && !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
            throw new \DomainException('Enter the Kubernetes namespace where the Argo CD Applications are registered.');
        }
    }

    public static function validVmTarget(string $target): bool
    {
        return (bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_.-]*@[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$/D', $target);
    }

    public function importAnsibleVms(array $hosts): int
    {
        return $this->store->db->transactional(function () use ($hosts): int {
            $names = $targets = [];
            foreach ($this->store->iterate("SELECT name, data FROM inventory_connections WHERE kind = 'vm'") as $connection) {
                $names[strtolower($connection['name'])] = true;
                $targets[strtolower($connection['data']['target'])] = true;
            }
            $imported = 0;
            foreach ($hosts as $host) {
                $name = strtolower($host['name']);
                $target = strtolower($host['target']);
                if (isset($names[$name]) || isset($targets[$target])) {
                    continue;
                }
                $data = [
                    'target' => $host['target'], 'port' => $host['port'], 'credential' => $host['credential'],
                    'docker_inventory' => '', 'docker_sudo' => '', 'interval' => 0, 'next_at' => 0,
                    'ansible_groups' => $host['groups'],
                ];
                $imported += $this->store->db->executeStatement(
                    "INSERT INTO inventory_connections (id, kind, name, data) VALUES (?, 'vm', ?, ?) ON CONFLICT (id) DO NOTHING",
                    [hash('sha256', 'ansible/vm/'.$target), $host['name'], Store::json($data)],
                );
                $names[$name] = $targets[$target] = true;
            }

            return $imported;
        });
    }

    public function remove(string $id): void
    {
        $row = $this->get($id) ?? throw new \DomainException('This connection does not exist.');
        if ($this->active($row['data'])) {
            throw new \DomainException('Wait for the inventory job to finish before removing the connection.');
        }
        if (!$this->store->db->delete('inventory_connections', ['id' => $id, 'data' => Store::json($row['data'])])) {
            throw new \DomainException('The connection changed during removal.');
        }
    }

    public function run(string $id, string $action, bool $dueOnly = false, ?string $afterPackageUpdate = null, bool $afterDiscovery = false): bool
    {
        if (!in_array($action, self::JOB_OPERATIONS, true)) {
            throw new \DomainException('Choose an inventory action.');
        }
        return $this->store->db->transactional(function () use ($id, $action, $dueOnly, $afterPackageUpdate, $afterDiscovery): bool {
            $row = $this->get($id) ?? throw new \DomainException('This connection does not exist.');
            $previous = $row['data'];
            if ('scan' === $action && $afterDiscovery) {
                if ('complete' !== (self::lastDiscovery($previous)['status'] ?? null)) {
                    throw new \DomainException('Complete discovery before requesting a scan from Getting started.');
                }
                if (self::needsManagedCredential($row)) {
                    throw new \DomainException('Set a managed credential reference for this connection before running a scan.');
                }
                if (null !== ($blocker = self::checklistScanBlocker($row))) {
                    throw new \DomainException($blocker);
                }
            }
            if ('discover' === $action && self::needsManagedCredential($row)) {
                throw new \DomainException('Set a managed credential reference for this connection before running discovery.');
            }
            if ('argo' === $action && ('cluster' !== $row['kind'] || empty($previous['argo_namespace']) || '' === self::argoCredential($previous))) {
                throw new \DomainException('Set an Argo CD namespace and managed read credential in Delivery integrations.');
            }
            if ('delivery' === $action && (!in_array($row['kind'], ['vm', 'cluster'], true) || self::needsManagedCredential($row))) {
                throw new \DomainException('Choose an SSH or Kubernetes connection with configured access.');
            }
            if ($dueOnly && (empty($previous['interval']) || ($previous['next_at'] ?? PHP_INT_MAX) > time() || $this->active($previous))) {
                return false;
            }
            if ($this->active($previous)) {
                throw new \DomainException('This connection already has a queued or running job.');
            }
            $token = bin2hex(random_bytes(12));
            $data = array_replace($previous, ['token' => $token, 'status' => 'queued', 'operation' => $action, 'queued_at' => time(), 'result' => '', 'finished_at' => null]);
            if ('scan' === $action && null !== $afterPackageUpdate) {
                $data['scan_after_package_update'] = $afterPackageUpdate;
            } else {
                unset($data['scan_after_package_update']);
            }
            $lastScan = self::lastScan($previous);
            if (null !== $lastScan) {
                $data['last_scan'] = $lastScan;
            }
            $lastDiscovery = self::lastDiscovery($previous);
            if (null !== $lastDiscovery) {
                $data['last_discovery'] = $lastDiscovery;
            }
            if (!$this->update($row, $data)) {
                if ($dueOnly) {
                    return false;
                }
                throw new \DomainException('The connection changed before the job could be queued.');
            }
            $this->bus->dispatch(new RunInventory($id, $token, $action));

            return true;
        });
    }

    public function packageScanStatus(array $data, string $job): array
    {
        $busy = $this->active($data);
        $recorded = self::lastScan($data);
        $linked = ($recorded['after_package_update'] ?? null) === $job;
        $state = $linked ? $recorded['status'] : null;
        if (($data['scan_after_package_update'] ?? null) === $job && 'scan' === ($data['operation'] ?? null)
            && in_array($data['status'] ?? null, self::ACTIVE_JOB_STATES, true)) {
            $state = $busy ? $data['status'] : 'overdue';
        }

        return [
            'busy' => $busy, 'status' => $state,
            'finished_at' => $linked ? ($recorded['finished_at'] ?? null) : null,
            'failure_reason' => $linked ? ($recorded['failure_reason'] ?? null) : null,
        ];
    }

    public function enqueueDue(int $limit): array
    {
        $queued = [];
        foreach ($this->all() as $row) {
            if ($this->run($row['id'], 'scan', true)) {
                $queued[$row['id']] = 'queued';
                if (count($queued) >= $limit) {
                    break;
                }
            }
        }

        return $queued;
    }

    public function scheduledScans(int $now, bool $includeFailureDetails = false, bool $includeRows = true): array
    {
        $query = $this->scheduledScanQuery($includeFailureDetails && $includeRows);
        $columns = $includeRows ? 'scheduled.*, ' : '';
        $window = $includeRows ? ' OVER ()' : '';
        $order = $includeRows ? " ORDER BY CASE state WHEN 'due' THEN 0 WHEN 'running' THEN 1 WHEN 'queued' THEN 2 ELSE 3 END,
            CASE WHEN next_at IS NULL THEN 1 ELSE 0 END, next_at, id LIMIT 100" : '';
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT {$columns}COUNT(*)$window AS total,
                COALESCE(SUM(CASE WHEN state = 'due' THEN 1 ELSE 0 END)$window, 0) AS due_count,
                MIN(CASE WHEN state = 'due' THEN next_at END)$window AS oldest_due
             FROM ($query) scheduled$order",
            ['scan_now' => $now],
            ['scan_now' => ParameterType::INTEGER],
        );
        $summary = $rows[0] ?? [];
        $aggregateFields = array_flip(['total', 'due_count', 'oldest_due']);

        return [
            'rows' => $includeRows ? array_map(static fn (array $row): array => array_replace(
                array_diff_key($row, $aggregateFields), ['has_failed_images' => (bool) $row['has_failed_images']],
            ), $rows) : [],
            'total' => (int) ($summary['total'] ?? 0),
            'due_count' => (int) ($summary['due_count'] ?? 0),
            'oldest_due' => isset($summary['oldest_due']) ? (int) $summary['oldest_due'] : null,
        ];
    }

    /** The caller binds scan_now as an integer Unix timestamp. */
    public function scheduledScanQuery(bool $includeFailureDetails): string
    {
        $interval = $this->store->jsonText('data', 'interval');
        $next = $this->store->jsonText('data', 'next_at');
        $status = $this->store->jsonText('data', 'status');
        $queued = 'CAST('.$this->store->jsonText('data', 'queued_at').' AS BIGINT)';
        $activeJob = "$status IN ('queued', 'running') AND COALESCE($queued, 0) > :scan_now - ".self::ACTIVE_JOB_SECONDS;
        $operation = $this->store->jsonText('data', 'operation');
        $finished = $this->store->jsonText('data', 'finished_at');
        $lastScan = $this->store->jsonText('data', 'last_scan');
        $lastStatus = $this->store->jsonText($lastScan, 'status');
        $lastFinished = $this->store->jsonText($lastScan, 'finished_at');
        $legacyScan = "$operation = 'scan' AND $status IN ('complete', 'failed')";
        $failureReason = 'NULL';
        $hasFailedImages = '0';
        if ($includeFailureDetails) {
            $lastFailure = $this->store->jsonText($lastScan, 'failure_reason');
            $hasFailedImages = "CASE WHEN kind = 'cluster' AND ".$this->recordedFailedImagesSql($lastScan).' THEN 1 ELSE 0 END';
            $latestResult = $this->store->jsonText('data', 'result');
            $currentFailure = "CASE WHEN $operation = 'scan' AND $status = 'failed' THEN $latestResult END";
            $failureReason = "CASE WHEN $lastScan IS NULL THEN $currentFailure
                WHEN $lastStatus = 'failed' THEN COALESCE($lastFailure,
                    CASE WHEN COALESCE($lastFinished, '') = COALESCE($finished, '') THEN $currentFailure END) END";
        }
        return "SELECT id, name, kind, CAST($next AS BIGINT) AS next_at, $operation AS operation,
                CASE WHEN $lastScan IS NOT NULL THEN $lastStatus WHEN $legacyScan THEN $status END AS outcome,
                CASE WHEN $lastScan IS NOT NULL THEN $lastFinished WHEN $legacyScan THEN $finished END AS checked_at,
                $failureReason AS failure_reason, $hasFailedImages AS has_failed_images,
                CASE WHEN $activeJob THEN $queued END AS queued_at,
                CASE WHEN $activeJob THEN $status
                     WHEN CAST($next AS BIGINT) <= :scan_now THEN 'due' ELSE 'scheduled' END AS state
             FROM inventory_connections WHERE CAST($interval AS BIGINT) > 0";
    }

    private function recordedFailedImagesSql(string $lastScan): string
    {
        $status = $this->store->jsonText($lastScan, 'status');
        $images = $this->store->jsonText($lastScan, 'failed_images');

        return "$status = 'failed' AND COALESCE($images, '[]') <> '[]'";
    }

    /** @return array{name: string, images: list<string>}|null */
    public function failedScanImages(string $id): ?array
    {
        $connection = $this->get($id);
        if ('cluster' !== ($connection['kind'] ?? null)) {
            return null;
        }
        $lastScan = self::lastScan($connection['data']);

        return [
            'name' => $connection['name'],
            'images' => 'failed' === ($lastScan['status'] ?? null) ? ($lastScan['failed_images'] ?? []) : [],
        ];
    }

    private static function checklistScanBlocker(array $row): ?string
    {
        return match ($row['kind']) {
            'docker' => 'Configure Docker scans on individual image assets.',
            'cluster' => preg_match('/[^\s,]/', $row['data']['registries'] ?? '') ? null
                : 'Add registry hostnames in the connection settings to scan cluster images.',
            default => null,
        };
    }

    private static function lastScan(array $data): ?array
    {
        $recorded = is_array($data['last_scan'] ?? null) ? $data['last_scan'] : null;
        if ('scan' === ($data['operation'] ?? null) && in_array($data['status'] ?? null, ['complete', 'failed'], true)) {
            $finishedAt = $data['finished_at'] ?? null;
            $recorded ??= ['status' => $data['status'], 'finished_at' => $finishedAt];
            if ('failed' === $data['status'] && 'failed' === ($recorded['status'] ?? null)
                && ($recorded['finished_at'] ?? null) === $finishedAt && isset($data['result'])) {
                $recorded += ['failure_reason' => $data['result']];
            }
        }

        return $recorded;
    }

    private static function lastDiscovery(array $data): ?array
    {
        if (is_array($data['last_discovery'] ?? null)) {
            return $data['last_discovery'];
        }
        if ('discover' === ($data['operation'] ?? null) && in_array($data['status'] ?? null, ['complete', 'failed'], true)) {
            return [
                'status' => $data['status'],
                'finished_at' => $data['finished_at'] ?? null,
                'result' => $data['result'] ?? null,
            ];
        }

        return !empty($data['last_discovery_at']) ? ['status' => 'complete', 'finished_at' => $data['last_discovery_at']] : null;
    }

    private static function scanSettings(string $kind, array $data): array
    {
        $settings = array_map(static fn (string $field) => $data[$field] ?? '', self::FIELDS[$kind]);

        return 'cluster' === $kind ? [...$settings, ...self::clusterScopeSettings($data)] : $settings;
    }

    private static function discoverySettings(string $kind, array $data): array
    {
        if ('cluster' !== $kind) {
            return self::scanSettings($kind, $data);
        }

        return [
            $data['target'] ?? '', $data['credential'] ?? '', $data['repository'] ?? '', $data['host_asset'] ?? '',
            ...self::clusterScopeSettings($data),
        ];
    }

    private static function clusterScopeSettings(array $data): array
    {
        $namespaces = self::clusterNamespaces($data);
        if (null !== $namespaces) {
            sort($namespaces, SORT_STRING);
        }

        return [$namespaces, $data['credential_mode'] ?? 'managed'];
    }

    private function active(array $data, ?int $now = null): bool
    {
        return in_array($data['status'] ?? '', self::ACTIVE_JOB_STATES, true) && ($data['queued_at'] ?? 0) + self::ACTIVE_JOB_SECONDS > ($now ?? time());
    }

    public function update(array $row, array $data): bool
    {
        return 1 === $this->store->db->update('inventory_connections', ['data' => Store::json($data)], [
            'id' => $row['id'], 'data' => Store::json($row['data']),
        ]);
    }
}
