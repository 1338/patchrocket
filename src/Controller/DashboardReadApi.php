<?php
declare(strict_types=1);

namespace App\Controller;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardReturnPath;
use App\Fleet\Analysis;
use App\Remediation\DashboardStatuses;
use App\Settings\Connections;
use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class DashboardReadApi
{
    private const PAGE_SIZE = 50;
    private const MAX_PAGE = 100000;
    private const FLEET_LIMIT = 100;
    private const PREVIEW_LIMIT = 20;
    private const IMPACT_ASSETS = ['container' => 'running', 'workload' => 'workloads', 'repository' => 'repositories'];
    private const ASSET_IDENTIFIERS = [
        'image' => ['digest' => 'Image digest', 'platform' => 'Platform'],
        'linux' => ['ssh_alias' => 'SSH target', 'hostname' => 'Hostname'],
        'repository' => ['subdirectory' => 'Repository scope', 'revision' => 'Scanned commit'],
        'binary' => ['path' => 'Installed path', 'digest' => 'Installed SHA-256'],
        'workload' => ['scope' => 'Discovery scope'],
        'container' => ['scope' => 'Discovery scope', 'context' => 'Docker context'],
        'namespace' => ['context' => 'Cluster context'],
    ];

    public function __construct(
        private readonly Store $store,
        private readonly Analysis $analysis,
        private readonly DashboardStatuses $statuses,
        private readonly Connections $connections,
    ) {
    }

    #[Route('/api/assets', name: 'api_assets', methods: ['GET'])]
    public function assets(Request $request): JsonResponse
    {
        $kind = $request->query->getString('kind');
        $assetId = strtolower($request->query->getString('asset_id'));
        $assetId = preg_match('/^[a-f0-9]{64}$/D', $assetId) ? $assetId : '';
        $search = trim($request->query->getString('q'));
        $scan = $request->query->getString('scan');
        $schedule = $request->query->getString('schedule');
        $sort = $request->query->getString('sort');
        $page = $this->page($request);
        $filters = $params = [];
        $registryMatch = 'NULL';
        $selectParams = [];
        $from = $request->query->all()['from'] ?? null;
        $canManageSettings = 'admin' === $request->attributes->get('_dashboard_role');
        $scopeId = strtolower($request->query->getString('scope'));
        $assetScope = null;
        $scopeSql = '';
        if ('' !== $scopeId) {
            if (!preg_match('/^[a-f0-9]{64}$/D', $scopeId)) {
                return $this->response(['error' => 'Choose a valid asset scope.'], 400);
            }
            $scopeReturn = DashboardListContext::assetDetail($from, [DashboardListContext::ASSET_VULNERABILITIES_SECTION]);
            $scopeAsset = $this->store->row('SELECT name, kind FROM assets WHERE id = ?', [$scopeId]);
            $assetScope = [
                'id' => $scopeId,
                'name' => $scopeAsset['name'] ?? null,
                'return' => null !== $scopeReturn && '/assets/'.$scopeId === parse_url($scopeReturn, PHP_URL_PATH) ? $scopeReturn : null,
            ];
            if ('docker' === ($scopeAsset['kind'] ?? null) && $canManageSettings
                && ($checklistReturn = DashboardListContext::discoveryChecklist($from))) {
                $assetScope['checklistReturn'] = $checklistReturn;
            }
            $scopeSql = Inventory::scopeSql().' ';
            $filters[] = 'a.id IN (SELECT id FROM scope)';
        }
        $failedConnection = null;
        $connectionId = $request->query->getString('failed_connection');
        if ('' !== $connectionId) {
            if (!$canManageSettings) {
                return $this->response(['error' => 'Administrator access is required to view connection scan details.'], 403);
            }
            if (!preg_match('/^[a-f0-9]{32}$/D', $connectionId)) {
                return $this->response(['error' => 'Choose a Kubernetes connection.'], 400);
            }
            $batch = $this->connections->failedScanImages($connectionId);
            $images = $batch['images'] ?? [];
            $failedConnection = [
                'id' => $connectionId,
                'name' => $batch['name'] ?? null,
                'hasImages' => (bool) $images,
                'queueReturn' => DashboardReturnPath::queueSection($from),
                'checklistReturn' => DashboardListContext::discoveryChecklist($from),
            ];
            $kind = 'image';
            $ids = $this->store->db->getDatabasePlatform() instanceof SQLitePlatform
                ? 'SELECT value FROM json_each(?)'
                : 'SELECT value FROM jsonb_array_elements_text(CAST(? AS jsonb))';
            $filters[] = "a.id IN ($ids)";
            $params[] = Store::json($images);
        }
        $runningImage = strtolower($request->query->getString('running_image'));
        $runtimeScope = null;
        if ('' !== $runningImage) {
            if (!preg_match('/^[a-f0-9]{64}$/D', $runningImage)) {
                return $this->response(['error' => 'Choose a valid image.'], 400);
            }
            $image = $this->store->row("SELECT name, data FROM assets WHERE id = ? AND kind = 'image'", [$runningImage]);
            $digest = $image['data']['digest'] ?? null;
            $finding = DashboardListContext::findingDetailId($from, DashboardListContext::FINDING_RUNTIME_LINK);
            $runtimeScope = [
                'id' => $runningImage,
                'name' => $image['name'] ?? null,
                'digest' => $digest,
                'return' => null !== $finding && $this->store->db->fetchOne(
                    'SELECT 1 FROM findings WHERE id = ? AND asset_id = ?', [$finding, $runningImage],
                ) ? $from : null,
            ];
            $observations = Inventory::imageRuntimeObservationsSql($this->store);
            $filters[] = "a.id IN (SELECT id FROM ($observations) observed WHERE running = 1 AND (image_id = ? OR digest = ?))";
            array_push($params, $runningImage, $digest);
            $kind = 'container';
        }
        if ('' !== $kind) {
            $filters[] = 'a.kind = ?';
            $params[] = $kind;
        }
        if ('' !== $assetId) {
            $filters[] = 'a.id = ?';
            $params[] = $assetId;
        }
        $primary = $this->assetIdentifierSql(0);
        $secondary = $this->assetIdentifierSql(1);
        if ('' !== $search) {
            $lookup = preg_replace('~^(?:docker-pullable|docker|containerd|cri-o)://(?=(?:[^@\s]+@)?sha256:)~i', '', $search) ?? $search;
            $pattern = self::containsPattern($lookup);
            $searchFields = ['a.name', $primary, $secondary];
            $matches = array_map(static fn (string $field): string => "LOWER($field) LIKE LOWER(?) ESCAPE '!'", $searchFields);
            array_push($params, ...array_fill(0, count($searchFields), $pattern));
            if ('' === $kind || 'image' === $kind) {
                $registryMatch = $this->imageRegistryDigestMatchSql();
                $matches[] = "($registryMatch) IS NOT NULL";
                $params[] = $pattern;
                $selectParams[] = $pattern;
            }
            if (preg_match('/^[a-f0-9]{64}$/iD', $search)) {
                $matches[] = 'a.id = ?';
                $params[] = strtolower($search);
            }
            $filters[] = '('.implode(' OR ', $matches).')';
        }

        $outcome = $this->store->jsonText('a.data', 'scan_outcome');
        $source = $this->store->jsonText('a.data', 'scan_source');
        $scanned = $this->store->jsonText('a.data', 'scanned_at');
        $attempted = $this->store->jsonText('a.data', 'scan_attempted_at');
        $failedAt = DashboardScanEvidence::attemptSql($this->store);
        $scanState = DashboardScanEvidence::stateSql($this->store);
        if (in_array($scan, ['recorded', 'failed', 'unscanned'], true)) {
            $filters[] = "$scanState = ?";
            $params[] = $scan;
        } else {
            $scan = '';
        }
        $scheduleState = DashboardScanEvidence::scheduleStateSql(time());
        if (in_array($schedule, ['due', 'running', 'scheduled', 'unscheduled'], true)) {
            $filters[] = "$scheduleState = ?";
            $params[] = $schedule;
        } else {
            $schedule = '';
        }
        $order = match ($sort) {
            'newest' => 'a.observed_at DESC, ',
            'oldest' => 'a.observed_at ASC, ',
            'next-due' => "CASE WHEN ($scheduleState) IN ('due', 'scheduled') THEN 0 ELSE 1 END,
                CASE WHEN ($scheduleState) IN ('due', 'scheduled') THEN s.next_at END ASC, ",
            'scan-failures' => "CASE WHEN ($scanState) = 'failed' THEN 0 ELSE 1 END,
                CASE WHEN ($scanState) = 'failed' THEN COALESCE($failedAt, '') ELSE '' END DESC, ",
            default => '',
        };
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $resultsFrom = ' FROM assets a LEFT JOIN scan_schedules s ON s.id = a.id'.$where;
        $orderBy = $order.'a.kind, a.name, a.id';
        $scopeParams = '' === $scopeSql ? [] : [$scopeId];
        $assets = $this->store->db->fetchAllAssociative(
            $scopeSql."SELECT a.id, a.kind, a.name, a.observed_at, $outcome AS scan_outcome, $source AS scan_source,
                $scanned AS scanned_at, COALESCE($failedAt, $attempted) AS scan_attempted_at, $scanState AS scan_state,
                $scheduleState AS schedule_state, s.next_at AS schedule_next_at,
                $primary AS identity_primary, $secondary AS identity_secondary, $registryMatch AS matched_registry_digest
             $resultsFrom ORDER BY $orderBy".$this->window($page),
            [...$scopeParams, ...$selectParams, ...$params],
        );
        $visible = array_slice($assets, 0, self::PAGE_SIZE);

        return $this->response([
            'assets' => array_map(self::assetDisplayRow(...), $visible),
            'kinds' => $this->store->db->fetchFirstColumn('SELECT DISTINCT kind FROM assets ORDER BY kind'),
            'kind' => $kind,
            'assetId' => $assetId,
            'search' => $search,
            'scan' => $scan,
            'schedule' => $schedule,
            'sort' => '' === $order ? '' : $sort,
            'failedConnection' => $failedConnection,
            'assetScope' => $assetScope,
            'runtimeScope' => $runtimeScope,
            'scopedInventoryReturn' => null === $failedConnection && null === $assetScope && null === $runtimeScope
                ? DashboardListContext::scopedInventoryReturn($from, $canManageSettings) : null,
            'overviewScanReturn' => DashboardListContext::overviewScan($request->query->all()['overview_from'] ?? null),
            'page' => $page,
            'selectedPage' => $this->selectedResultPage(self::hiddenSelectedResult($request, 64, $visible),
                $scopeSql."SELECT a.id, ROW_NUMBER() OVER (ORDER BY $orderBy) AS result_position$resultsFrom", [...$scopeParams, ...$params]),
            'next' => count($assets) > self::PAGE_SIZE,
        ]);
    }

    private function assetIdentifierSql(int $position): string
    {
        $cases = [];
        foreach (self::ASSET_IDENTIFIERS as $kind => $fields) {
            $field = array_keys($fields)[$position] ?? null;
            if (null !== $field) {
                $cases[] = "WHEN '$kind' THEN ".$this->store->jsonText('a.data', $field);
            }
        }

        return 'CASE a.kind '.implode(' ', $cases).' END';
    }

    private function imageRegistryDigestMatchSql(): string
    {
        if ($this->store->db->getDatabasePlatform() instanceof SQLitePlatform) {
            $rows = "json_each(a.data, '$.repo_digests')";
            $value = 'ref.value';
            $strings = "json_type(a.data, '$.repo_digests') = 'array' AND ref.type = 'text'";
        } else {
            $digests = "(CAST(a.data AS jsonb)->'repo_digests')";
            $rows = "jsonb_array_elements(CASE WHEN jsonb_typeof($digests) = 'array' THEN $digests ELSE '[]'::jsonb END)";
            $value = "(ref.value #>> '{}')";
            $strings = "jsonb_typeof(ref.value) = 'string'";
        }

        $digestSuffix = '%@sha256:'.str_repeat('_', 64);

        return "CASE WHEN a.kind = 'image' THEN (
            SELECT $value FROM $rows AS ref WHERE $strings
                AND LOWER($value) LIKE '$digestSuffix' AND LOWER($value) LIKE LOWER(?) ESCAPE '!'
            ORDER BY $value LIMIT 1
        ) END";
    }

    private static function assetDisplayRow(array $asset): array
    {
        $asset['schedule_next_at'] = isset($asset['schedule_next_at']) ? (int) $asset['schedule_next_at'] : null;
        $labels = array_values(self::ASSET_IDENTIFIERS[$asset['kind']] ?? []);
        $asset['identifiers'] = [];
        foreach (['identity_primary', 'identity_secondary'] as $position => $column) {
            $value = $asset[$column];
            if (is_string($value) && '' !== $value && $value !== $asset['name']) {
                $asset['identifiers'][] = ['label' => $labels[$position], 'value' => $value];
            }
            unset($asset[$column]);
        }
        $registryDigest = $asset['matched_registry_digest'];
        if (Inventory::isRegistryDigest($registryDigest) && $registryDigest !== $asset['name']
            && !in_array($registryDigest, array_column($asset['identifiers'], 'value'), true)) {
            $asset['identifiers'][] = ['label' => 'Registry digest', 'value' => $registryDigest];
        }
        unset($asset['matched_registry_digest']);

        return $asset;
    }

    #[Route('/api/remediations', name: 'api_remediations', methods: ['GET'])]
    public function remediations(Request $request): JsonResponse
    {
        $context = DashboardListContext::parameters($request, DashboardListContext::FLEET, 'fleet_from');
        $status = $request->query->getString('status');
        $strategy = $request->query->getString('strategy');
        $search = trim($request->query->getString('q'));
        $attempt = strtolower($request->query->getString('attempt'));
        $attempt = preg_match('/^[a-f0-9]{24}$/D', $attempt) ? $attempt : '';
        $executable = strtolower($request->query->getString('executable'));
        $executable = preg_match('/^[a-f0-9]{64}$/D', $executable) ? $executable : '';
        $executableFrom = DashboardListContext::executables($request->query->all()['executable_from'] ?? null);
        $month = $request->query->getString('month');
        if (!preg_match('/^[0-9]{4}-(?:0[1-9]|1[0-2])$/D', $month)) {
            $month = '';
        }
        $page = $this->page($request);
        $filters = $params = [];
        $executableScope = "strategy = 'standalone-binary' AND executable_id = ?";
        if ('' !== $status) {
            $group = DashboardStatuses::GROUPS[$status] ?? [$status];
            $filters[] = 'display_status IN ('.implode(', ', array_fill(0, count($group), '?')).')';
            $params = $group;
        }
        if ('' !== $strategy) {
            $filters[] = 'strategy = ?';
            $params[] = $strategy;
        }
        if ('' !== $attempt) {
            $filters[] = 'id = ?';
            $params[] = $attempt;
        }
        if ('' !== $executable) {
            $filters[] = $executableScope;
            $params[] = $executable;
        }
        if ('' !== $search) {
            $filters[] = "(LOWER(title) LIKE LOWER(?) ESCAPE '!' OR LOWER(id) LIKE LOWER(?) ESCAPE '!'
                OR LOWER(advisory) LIKE LOWER(?) ESCAPE '!' OR LOWER(asset_name) LIKE LOWER(?) ESCAPE '!')";
            $pattern = self::containsPattern($search);
            array_push($params, $pattern, $pattern, $pattern, $pattern);
        }
        if ('' !== $month) {
            $filters[] = 'SUBSTR(created_at, 1, 7) = ?';
            $params[] = $month;
        }
        $query = $this->statuses->reviewQuery();
        $where = $filters ? ' WHERE '.implode(' AND ', $filters) : '';
        $resultsFrom = " FROM ($query) remediations$where";
        $orderBy = 'created_at DESC, id DESC';
        $columns = 'id, status, strategy, created_at, title, display_status, advisory, asset_name, retry_of, review_section';
        $changes = $this->store->db->fetchAllAssociative(
            "SELECT $columns$resultsFrom ORDER BY $orderBy".$this->window($page),
            $params,
        );
        $visible = array_slice($changes, 0, self::PAGE_SIZE);
        $selectedId = self::hiddenSelectedResult($request, 24, $visible);
        $selection = null;
        if (null !== $selectedId) {
            $scope = '' === $executable ? '' : " AND $executableScope";
            $selection = $this->store->db->fetchAssociative(
                "SELECT $columns FROM ($query) remediations WHERE id = ?$scope",
                '' === $executable ? [$selectedId] : [$selectedId, $executable],
            ) ?: null;
        }
        $listed = $this->statuses->withApprovalHolds(null === $selection ? $visible : [...$visible, $selection]);
        if (null !== $selection) {
            $selection = array_pop($listed);
        }
        $statusQuery = $this->statuses->query('c.id');

        return $this->response([
            'changes' => $listed,
            'selected_change' => $selection,
            'statuses' => $this->store->db->fetchFirstColumn("SELECT DISTINCT display_status FROM ($statusQuery) remediations ORDER BY display_status"),
            'status_groups' => array_keys(DashboardStatuses::GROUPS),
            'status' => $status,
            'strategies' => $this->store->db->fetchFirstColumn('SELECT DISTINCT strategy FROM changes ORDER BY strategy'),
            'strategy' => $strategy,
            'month' => $month,
            'fleet_from' => $context['fleet_from'] ?? null,
            'executable_from' => $executableFrom,
            'executable' => '' === $executable ? null : [
                'id' => $executable,
                'name' => $this->store->db->fetchOne("SELECT name FROM assets WHERE id = ? AND kind = 'binary'", [$executable]) ?: $executable,
            ],
            'search' => $search,
            'attempt' => $attempt,
            'page' => $page,
            'selectedPage' => $this->selectedResultPage($selectedId,
                "SELECT id, ROW_NUMBER() OVER (ORDER BY $orderBy) AS result_position$resultsFrom", $params),
            'next' => count($changes) > self::PAGE_SIZE,
        ]);
    }

    #[Route('/api/fleet', name: 'api_fleet', methods: ['GET'])]
    public function fleet(Request $request): JsonResponse
    {
        $impactSearch = trim($request->query->getString('impact_q'));
        $impactRunning = $request->query->getBoolean('impact_running');
        $impactPage = $this->page($request, 'impact_page');
        $impactOffset = ($impactPage - 1) * self::FLEET_LIMIT;
        $impactTerms = preg_split('/\s+/', $impactSearch, flags: PREG_SPLIT_NO_EMPTY) ?: [];
        $packageSearch = trim($request->query->getString('package_q'));
        $packagePage = $this->page($request, 'package_page');
        $packageOffset = ($packagePage - 1) * self::FLEET_LIMIT;
        $report = $this->analysis->report(includeFindings: false);
        $matchingExposure = array_filter($report['exposure'], static function (array $group) use ($impactRunning, $impactTerms): bool {
            if ($impactRunning && !$group['running']) {
                return false;
            }
            $text = implode(' ', [$group['advisory'], $group['package'], $group['type']]);
            foreach ($impactTerms as $term) {
                if (false === stripos($text, $term)) {
                    return false;
                }
            }

            return true;
        });
        $exposure = array_map(static function (array $group): array {
            return [
                'advisory' => $group['advisory'],
                'package' => $group['package'],
                'type' => $group['type'],
                'rank' => $group['rank'],
                'priority' => $group['priority'],
                'fix_available' => $group['fix_available'],
                'running' => (object) array_slice($group['running'], 0, self::PREVIEW_LIMIT, true),
                'workloads' => (object) array_slice($group['workloads'], 0, self::PREVIEW_LIMIT, true),
                'repositories' => (object) array_slice($group['repositories'], 0, self::PREVIEW_LIMIT, true),
                'running_count' => count($group['running']),
                'workload_count' => count($group['workloads']),
                'repository_count' => count($group['repositories']),
            ];
        }, array_slice($matchingExposure, $impactOffset, self::FLEET_LIMIT));
        $matchingPackages = '' === $packageSearch ? $report['shared'] : array_filter(
            $report['shared'], static fn (string $name): bool => false !== stripos($name, $packageSearch), ARRAY_FILTER_USE_KEY,
        );
        $dependency = $this->sharedDependencyView($request, $report['shared']);
        $packagePreviews = null === $dependency ? array_slice($matchingPackages, $packageOffset, self::FLEET_LIMIT, true) : [];
        $shared = array_map(static fn (array $assets): array => [
            'asset_count' => count($assets),
            'assets' => (object) array_map(
                static fn (array $versions): array => array_slice($versions, 0, self::PREVIEW_LIMIT),
                array_slice($assets, 0, self::PREVIEW_LIMIT, true),
            ),
        ], $packagePreviews);
        $assetIds = [];
        foreach ($shared as $group) {
            $assetIds += (array) $group['assets'];
        }
        $history = $report['history'];
        $monthCount = count($history['months']);
        $monthPage = $this->page($request, 'month_page');
        $monthOffset = ($monthPage - 1) * self::FLEET_LIMIT;
        $history['months'] = (object) array_slice($history['months'], $monthOffset, self::FLEET_LIMIT, true);

        return $this->response(compact('exposure', 'history') + [
            'shared' => (object) $shared, 'shared_asset_names' => (object) $this->assetNames(array_keys($assetIds)),
            'dependency' => $dependency,
            'impact_assets' => $this->impactAssetView($request, $report['exposure']),
            'exposure_count' => count($matchingExposure),
            'impact_search' => $impactSearch,
            'impact_running' => $impactRunning,
            'impact_page' => $impactPage,
            'impact_next' => $impactOffset + self::FLEET_LIMIT < count($matchingExposure),
            'shared_count' => count($matchingPackages),
            'package_search' => $packageSearch,
            'package_page' => $packagePage,
            'package_next' => $packageOffset + self::FLEET_LIMIT < count($matchingPackages),
            'month_count' => $monthCount,
            'month_page' => $monthPage,
            'month_next' => $monthOffset + self::FLEET_LIMIT < $monthCount,
        ]);
    }

    private function impactAssetView(Request $request, array $exposure): ?array
    {
        $selection = $request->query->getString('impact_assets');
        $parts = json_decode($selection, true);
        if (!is_array($parts) || !array_is_list($parts) || 4 !== count($parts)
            || array_filter($parts, 'is_string') !== $parts) {
            return null;
        }
        [$advisory, $package, $ecosystem, $kind] = $parts;
        $column = self::IMPACT_ASSETS[$kind] ?? null;
        if (null === $column) {
            return null;
        }

        $observations = [];
        foreach ($exposure as $group) {
            if ($advisory === $group['advisory'] && $package === $group['package'] && $ecosystem === $group['type']) {
                $observations = $group[$column];
                break;
            }
        }
        $search = trim($request->query->getString('impact_asset_q'));
        $page = $this->page($request, 'impact_asset_page');
        $offset = ($page - 1) * self::PREVIEW_LIMIT;
        $matches = '' === $search ? $observations : array_filter($observations, static fn (string $name, string $id): bool =>
            false !== stripos($name, $search) || false !== stripos($id, $search), ARRAY_FILTER_USE_BOTH);
        uksort($matches, static fn (string $a, string $b): int =>
            strnatcasecmp($matches[$a], $matches[$b]) ?: strcmp($a, $b));
        $matchCount = count($matches);

        return compact('selection', 'advisory', 'package', 'ecosystem', 'kind', 'search', 'page') + [
            'assets' => (object) array_slice($matches, $offset, self::PREVIEW_LIMIT, true),
            'asset_count' => count($observations),
            'match_count' => $matchCount,
            'last_page' => max(1, (int) ceil($matchCount / self::PREVIEW_LIMIT)),
            'next' => $offset + self::PREVIEW_LIMIT < $matchCount,
            'first_result' => $offset + 1,
        ];
    }

    private function sharedDependencyView(Request $request, array $shared): ?array
    {
        $package = trim($request->query->getString('dependency'));
        if ('' === $package) {
            return null;
        }
        $search = trim($request->query->getString('dependency_q'));
        $version = trim($request->query->getString('dependency_version'));
        $page = $this->page($request, 'dependency_page');
        $offset = ($page - 1) * self::PREVIEW_LIMIT;
        $observations = $shared[$package] ?? [];
        $names = $this->assetNames(array_keys($observations));
        $matches = array_filter($observations, static fn (array $versions, string $id): bool =>
            ('' === $version || in_array($version, array_map('strval', $versions), true))
            && ('' === $search || false !== stripos($names[$id] ?? '', $search) || false !== stripos($id, $search)), ARRAY_FILTER_USE_BOTH);
        uksort($matches, static fn (string $a, string $b): int =>
            strcasecmp($names[$a] ?? $a, $names[$b] ?? $b) ?: strcmp($a, $b));
        $assets = [];
        foreach (array_slice($matches, $offset, self::PREVIEW_LIMIT, true) as $id => $versions) {
            $assets[] = ['id' => $id, 'name' => $names[$id] ?? substr($id, 0, 12), 'versions' => array_map('strval', $versions)];
        }

        return compact('package', 'search', 'version', 'page', 'assets') + [
            'available' => isset($shared[$package]),
            'asset_count' => count($observations),
            'match_count' => count($matches),
            'next' => $offset + self::PREVIEW_LIMIT < count($matches),
        ];
    }

    private function assetNames(array $assetIds): array
    {
        $names = [];
        foreach (array_chunk($assetIds, 500) as $ids) {
            $names += $this->store->db->fetchAllKeyValue(
                'SELECT id, name FROM assets WHERE id IN (?)', [$ids], [ArrayParameterType::STRING],
            );
        }

        return $names;
    }

    private function page(Request $request, string $parameter = 'page'): int
    {
        return max(1, min(self::MAX_PAGE, $request->query->getInt($parameter, 1)));
    }

    private static function hiddenSelectedResult(Request $request, int $idLength, array $visible): ?string
    {
        $id = $request->query->all()['selected_result'] ?? null;
        if (!is_string($id) || !preg_match('/^[a-f0-9]{'.$idLength.'}$/D', $id) || in_array($id, array_column($visible, 'id'), true)) {
            return null;
        }

        return $id;
    }

    private function selectedResultPage(?string $id, string $rankedResults, array $parameters): ?int
    {
        if (null === $id) {
            return null;
        }
        $position = $this->store->db->fetchOne("SELECT result_position FROM ($rankedResults) ranked_results WHERE id = ?", [...$parameters, $id]);
        if (false === $position) {
            return null;
        }
        $page = intdiv((int) $position - 1, self::PAGE_SIZE) + 1;

        return $page <= self::MAX_PAGE ? $page : null;
    }

    private static function containsPattern(string $text): string
    {
        return '%'.strtr($text, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
    }

    private function window(int $page): string
    {
        return ' LIMIT '.(self::PAGE_SIZE + 1).' OFFSET '.(($page - 1) * self::PAGE_SIZE);
    }

    private function response(array $data, int $status = 200): JsonResponse
    {
        return new JsonResponse($data, $status, headers: ['Cache-Control' => 'private, no-store']);
    }
}
