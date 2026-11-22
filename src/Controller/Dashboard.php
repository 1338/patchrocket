<?php
declare(strict_types=1);

namespace App\Controller;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardReturnPath;
use App\Intelligence\ScanSchedules;
use App\Remediation\ApprovalPolicy;
use App\Remediation\BinaryTargets;
use App\Remediation\Change;
use App\Remediation\Changes;
use App\Remediation\DashboardPreparation;
use App\Remediation\DashboardPullRequests;
use App\Remediation\DashboardStatuses;
use App\Remediation\FindingHistory;
use App\Remediation\GitOps;
use App\Remediation\HarborRelease;
use App\Remediation\IndependentVerification;
use App\Remediation\JenkinsBuildStatus;
use App\Remediation\ReleaseTracking;
use App\Remediation\ReleaseTrackingSettingsConflict;
use App\Remediation\RemediationFieldError;
use App\Secrets\ConnectionCredentials;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class Dashboard extends AbstractController
{
    private const PREPARATION_DRAFT = 'preparation-draft';
    private const FINDINGS_PAGE_SIZE = 50;
    private const PRIORITY_FINDINGS_LIMIT = 6;
    private const ASSET_FINDINGS_PREVIEW_LIMIT = 25;
    private const FINDING_SUMMARY_FIELDS = ['advisory', 'severity', 'package', 'version', 'fixed', 'target'];

    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Changes $changes,
        private readonly DashboardPreparation $preparation,
        private readonly DashboardStatuses $dashboardStatuses,
    ) {
    }

    #[Route('/', name: 'overview', methods: ['GET'])]
    public function overview(Request $request, PreactPage $preact, ScanSchedules $scans, Connections $connections): Response
    {
        $scanState = DashboardScanEvidence::stateSql($this->store);
        $assetGroups = $this->store->rows(
            "SELECT a.kind, $scanState AS scan_state, COUNT(*) AS total
             FROM assets a LEFT JOIN scan_schedules s ON s.id = a.id
             GROUP BY a.kind, scan_state ORDER BY a.kind",
        );
        $assetCounts = [];
        $scanCoverage = ['recorded' => 0, 'failed' => 0, 'unscanned' => 0];
        foreach ($assetGroups as ['kind' => $kind, 'scan_state' => $state, 'total' => $total]) {
            $assetCounts[$kind] = ($assetCounts[$kind] ?? 0) + (int) $total;
            if (isset($scanCoverage[$state])) {
                $scanCoverage[$state] += (int) $total;
            }
        }
        $assets = [];
        foreach ($assetCounts as $kind => $total) {
            $assets[] = ['kind' => $kind, 'total' => $total];
        }
        $remediations = $this->dashboardStatuses->query('c.id');
        $changes = $this->store->rows("SELECT display_status AS status, COUNT(*) AS total FROM ($remediations) c GROUP BY display_status");
        $counts = array_column($changes, 'total', 'status');
        $severityField = $this->findingField('severity');
        $fixField = $this->findingField('fixed');
        $countsBySeverity = $this->store->rows("SELECT $severityField AS severity, COUNT(*) AS total FROM findings f WHERE active = 1 GROUP BY $severityField");
        $severity = array_column($countsBySeverity, 'total', 'severity');

        $recent = $this->store->db->fetchAllAssociative($this->dashboardStatuses->reviewQuery().' ORDER BY c.created_at DESC, c.id DESC LIMIT 5');
        $now = time();
        $totalAssets = array_sum($assetCounts);
        $inventorySetup = null;
        if (0 === $totalAssets && 'admin' === $request->attributes->getString('_dashboard_role', 'admin')) {
            $saved = $this->store->db->fetchFirstColumn('SELECT id FROM inventory_connections ORDER BY id LIMIT 2');
            $hasConnections = [] !== $saved;
            $active = $hasConnections && $connections->hasActiveInventoryWork('', operation: 'discover');
            $candidate = $hasConnections && !$active ? $connections->firstConnectionWithoutCredentialBlocker() : null;
            $needsCredentials = $hasConnections && !$active && null === $candidate;
            $attention = null === $candidate ? null : $connections->discoveryNeedingAttention($now);
            $selected = $attention['id'] ?? $candidate ?? (1 === count($saved) ? $saved[0] : null);
            $parameters = match (true) {
                null !== $selected => ['connection' => $selected],
                $needsCredentials => ['discovery_credentials' => 1],
                default => [],
            };
            $inventorySetup = [
                'has_connections' => $hasConnections,
                'discovery_active' => $active,
                'discovery_attention' => $needsCredentials ? 'credential_required' : ($attention['state'] ?? null),
                'url' => $this->generateUrl('settings_getting-started', $parameters + [
                    '_fragment' => $hasConnections ? DashboardListContext::DISCOVERY_SECTION : DashboardListContext::GETTING_STARTED_CONNECTIONS_SECTION,
                ]),
            ];
        }

        $assetScans = $scans->dueBacklog($now);
        $connectionScans = $connections->scheduledScans($now, includeRows: false);

        return $preact->render('overview', [
            'assets' => $assets, 'findings' => $this->findingTableRows($this->findings(self::PRIORITY_FINDINGS_LIMIT)['rows']),
            'severity' => $severity, 'total_assets' => $totalAssets, 'scan_coverage' => $scanCoverage, 'inventory_setup' => $inventorySetup,
            'scans_due' => [
                'assets' => $assetScans['due_count'],
                'connections' => $connectionScans['due_count'],
            ],
            'scan_oldest_due' => [
                'assets' => $assetScans['oldest_due'],
                'connections' => $connectionScans['oldest_due'],
            ],
            'total_findings' => array_sum($severity),
            'fixable' => $this->store->db->fetchOne("SELECT COUNT(*) FROM findings f WHERE active = 1 AND $fixField <> ''"),
            'pending' => ($counts['awaiting_approval'] ?? 0),
            'running' => array_sum(array_intersect_key($counts, array_flip(DashboardStatuses::GROUPS['active']))),
            'verified' => array_sum(array_intersect_key($counts, array_flip(DashboardStatuses::GROUPS['verified']))),
            'failed' => $counts['failed'] ?? 0,
            'deployed' => array_sum(array_intersect_key($counts, array_flip(DashboardStatuses::GROUPS['deployment_verified']))),
            'recent' => $this->dashboardStatuses->withApprovalHolds($recent),
        ]);
    }

    #[Route('/assets', name: 'assets', methods: ['GET'])]
    public function assets(PreactPage $preact): Response
    {
        return $preact->render('assets');
    }

    #[Route('/assets/{id}', name: 'asset', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function asset(string $id, Request $request, PreactPage $preact, CsrfTokenManagerInterface $tokens, VmPackageDashboard $packages): Response
    {
        $context = DashboardListContext::asset($request);
        $asset = $this->assetWithScanState($id);
        $data = $asset['data'];
        $admin = 'admin' === $request->attributes->get('_dashboard_role', 'admin');
        $backPath = parse_url($context['from'] ?? '', PHP_URL_PATH);
        $findingDetail = DashboardListContext::findingDetailId($context['from'] ?? null);
        $findingSource = DashboardListContext::findingSource($context['from'] ?? null);
        $relatedAsset = DashboardListContext::relatedAsset($context['from'] ?? null);
        $packageQueue = DashboardListContext::vmPackageQueue($context['from'] ?? null);
        if (!$admin && (DashboardListContext::GETTING_STARTED === $backPath || $packageQueue)) {
            $context = [];
            $backPath = null;
            $packageQueue = null;
        }
        $scan = self::scanEvidence($asset);
        $retry = null;
        if ('failed' === $asset['scan_state'] && 'failed' === $asset['schedule_outcome']
            && $asset['schedule_attempted_at'] && $asset['schedule_attempted_at'] === $asset['failed_at']) {
            $scan['schedule_state'] = $asset['schedule_state'];
            if ($admin) {
                $scan['failure_reason'] = $asset['schedule_failure_reason'];
                if ('scheduled' === $scan['schedule_state']) {
                    $retry = $this->generateUrl('settings_update', ['action' => 'scan-retry', 'return_to_asset' => '1'] + $context);
                }
            }
        }
        $canManageScan = $admin && in_array($asset['kind'], ['image', 'repository'], true);
        $schedule = 'unscheduled' === $asset['schedule_state'] ? null : [
            'state' => $asset['schedule_state'],
            'interval_minutes' => intdiv((int) $asset['schedule_interval_seconds'], 60),
            'next_at' => (int) $asset['schedule_next_at'],
            'attempted_at' => $asset['schedule_attempted_at'],
            'outcome' => $asset['schedule_outcome'],
        ];
        $binary = 'binary' === $asset['kind'];
        $infrastructure = 'infrastructure' === ($data['role'] ?? null);
        $report = $infrastructure ? ($data['infra_report'] ?? null) : null;
        $inventory = null;
        if ($report) {
            $inventory = [
                'skipped' => (int) ($report['skipped'] ?? 0),
                'resources' => array_map(fn (array $entry): array => self::detailFields($entry, [
                    'kind', 'name', 'namespace', 'namespace_from', 'path',
                ]) + ['observed_url' => $this->assetDetailUrl($entry['observed'] ?? null)], array_values($report['resources'] ?? [])),
                'external' => array_map(static fn (array $entry): array => self::detailFields($entry, [
                    'kind', 'target', 'path',
                ]), array_values($report['external'] ?? [])),
                'terraform' => self::detailStrings($report['terraform'] ?? []),
            ];
        }

        $packageUpdates = 'admin' === $request->attributes->get('_dashboard_role') ? $packages->panel($asset, $context) : null;
        $csrf = $retry ? ['scan-retry' => $tokens->getToken('settings-scan-retry')->getValue()] : [];
        if ($packageUpdates) {
            $csrf['vm-package'] = $tokens->getToken('vm-package-'.$id)->getValue();
        }
        // Keep list filters when opening another finding from an affected asset.
        $previewContext = null !== $findingDetail
            ? DashboardListContext::parameters(Request::create($context['from']), DashboardListContext::FINDINGS)
            : $context;
        $previewUrl = $this->generateUrl('asset', ['id' => $id] + $previewContext);

        $findingsContext = $previewContext;
        $previewFrom = $previewContext['from'] ?? '';
        if (in_array(parse_url($previewFrom, PHP_URL_PATH), DashboardListContext::FINDINGS, true)) {
            $previousPanel = DashboardListContext::assetDetail(Request::create($previewFrom)->query->all()['from'] ?? null,
                [DashboardListContext::ASSET_VULNERABILITIES_SECTION]);
            if (null !== $previousPanel) {
                // Reuse the panel's upstream context when opening a new scope from a related asset.
                $findingsContext = DashboardListContext::asset(Request::create($previousPanel));
            }
        }
        $findingsParameters = ['asset' => $id, 'from' => $this->generateUrl('asset', [
            'id' => $id, '_fragment' => DashboardListContext::ASSET_VULNERABILITIES_SECTION,
        ] + $findingsContext)];
        $scanState = DashboardScanEvidence::stateSql($this->store);
        $summary = $this->store->row(Inventory::scopeSql().", coverage AS (
            SELECT $scanState AS state FROM scope JOIN assets a ON a.id = scope.id LEFT JOIN scan_schedules s ON s.id = a.id
        ) SELECT
            (SELECT COUNT(*) FROM findings WHERE asset_id IN (SELECT id FROM scope) AND active = 1) AS active_count,
            CASE WHEN EXISTS(SELECT 1 FROM findings WHERE asset_id IN (SELECT id FROM scope) AND active = 0) THEN 1 ELSE 0 END AS has_history,
            COUNT(CASE WHEN state = 'recorded' THEN 1 END) AS recorded,
            COUNT(CASE WHEN state = 'failed' THEN 1 END) AS failed,
            COUNT(CASE WHEN state = 'unscanned' THEN 1 END) AS unscanned
        FROM coverage", [$id]);
        $registryDigests = [];
        if ('image' === $asset['kind'] && is_array($data['repo_digests'] ?? null)) {
            $digests = array_filter($data['repo_digests'], static fn (mixed $digest): bool =>
                Inventory::isRegistryDigest($digest) && $digest !== $asset['name'] && $digest !== ($data['digest'] ?? null));
            $registryDigests = array_values(array_unique($digests));
        }

        return $preact->render('asset', [
            'title' => $asset['name'],
            'asset' => self::detailFields($asset, ['id', 'kind', 'observed_at']),
            'scan' => $scan,
            'scan_coverage' => array_map('intval', array_intersect_key($summary, array_flip(['recorded', 'failed', 'unscanned']))),
            'scan_schedule' => $schedule,
            'package_updates' => $packageUpdates,
            'facts' => self::detailFields($data, [
                'reference', 'digest', 'image', 'revision', 'role', 'infra_context', 'hostname', 'tools', 'ssh_alias',
                'os', 'kernel', 'manager', 'controller', 'platform', 'discovery_source', 'collected_at', 'subdirectory',
                'discovery_state', 'scope', 'phase', 'health', 'running',
            ]) + ($binary ? self::detailFields($data, ['path']) : []),
            'declared_images' => isset($data['declared_images']) ? self::detailStrings($data['declared_images']) : null,
            'registry_digests' => $registryDigests,
            'components' => array_map(static fn (array $item): array => self::detailFields($item, ['group', 'name', 'version', 'purl']),
                array_values($data['sbom']['components'] ?? $data['components'] ?? [])),
            'build_sources' => $this->detailBuildSources($data),
            'delivery_sources' => $this->detailDeliverySources($asset),
            'argo' => 'argo-application' === $asset['kind'] ? $this->detailArgo($data) : null,
            'infrastructure' => $infrastructure,
            'infra_report' => $inventory,
            'links' => array_map(fn (array $link): array => $this->detailAssetLink($link) + [
                'edge' => Inventory::linkFingerprint($link['source_id'], $link['kind'], $link['target_id']),
                'outgoing' => $link['source_id'] === $id,
            ], $this->inventory->links($id)),
            'findings' => array_map(fn (array $finding): array => $this->detailFinding($finding, assetPreview: $previewUrl),
                $this->findings(self::ASSET_FINDINGS_PREVIEW_LIMIT, filters: ['asset' => $id])['rows']),
            'finding_count' => (int) $summary['active_count'],
            'urls' => [
                'back' => $context['from'] ?? $this->generateUrl('assets'),
                'back_label' => match (true) {
                    null !== $findingDetail => 'Affected finding',
                    null !== $findingSource => $findingSource['label'],
                    null !== $relatedAsset => 'Related assets',
                    null !== $packageQueue => 'VM package updates',
                    DashboardListContext::OVERVIEW === $backPath => 'Overview',
                    DashboardListContext::QUEUE === $backPath => 'Queue',
                    DashboardListContext::GETTING_STARTED === $backPath => 'Getting started',
                    DashboardListContext::EXECUTABLES === $backPath => 'Standalone executables',
                    in_array($backPath, DashboardListContext::FINDINGS, true) => 'Vulnerabilities',
                    in_array($backPath, DashboardListContext::FLEET, true) => 'Fleet',
                    default => 'Asset inventory',
                },
                'scan_retry' => $retry,
                'scanner_settings' => $canManageScan && 'failed' === $scan['scan_state']
                    ? $this->assetScanSettingsUrl($id, $context, 'scan-failure', 'scanner-worker') : null,
                'sbom' => isset($data['sbom']) ? $this->generateUrl('sbom', ['id' => $id]) : null,
                'scan_schedule' => $canManageScan
                    ? $this->assetScanSettingsUrl($id, $context, 'failed' === $scan['scan_state'] ? 'scan-failure' : 'asset-title') : null,
                'first_scan_schedule' => $canManageScan && !$schedule && 'unscanned' === $scan['scan_state']
                    ? $this->assetScanSettingsUrl($id, $context, DashboardListContext::ASSET_VULNERABILITIES_SECTION) : null,
                'manage_scan_schedule' => $canManageScan && $schedule
                    ? $this->assetScanSettingsUrl($id, $context, DashboardListContext::ASSET_SCAN_SCHEDULE_SECTION) : null,
                'scan_queue' => $schedule && null === DashboardReturnPath::queueSection($context['from'] ?? null, 'scheduled-scans')
                    ? $this->generateUrl('frontend_dashboard', [
                        'view' => 'queue', 'scan_target' => 'asset', 'scan_q' => $id, '_fragment' => 'scheduled-scans/asset/'.$id,
                        'from' => $this->generateUrl('asset', ['id' => $id, '_fragment' => DashboardListContext::ASSET_SCAN_SCHEDULE_SECTION] + $context),
                    ]) : null,
                'approval_policy' => $admin && 'repository' === $asset['kind']
                    ? $this->generateUrl('settings_policy', ['repository' => $id, '_fragment' => DashboardListContext::APPROVAL_POLICY_EDITOR_SECTION,
                        'from' => $this->generateUrl('asset', ['id' => $id, '_fragment' => 'asset-title'] + $context),
                    ]) : null,
                'link_repository' => $admin && in_array($asset['kind'], Inventory::repositoryLinkAssetKinds('deployment'), true)
                    ? $this->generateUrl('settings_connections', [
                        'link_asset' => $id, '_fragment' => 'repository-links',
                        'from' => $this->generateUrl('asset', ['id' => $id, '_fragment' => DashboardListContext::ASSET_RELATIONS_SECTION] + $context),
                    ]) : null,
                'manage' => $binary && $admin
                    ? $this->generateUrl('settings_executables', [
                        'edit' => $id, '_fragment' => DashboardListContext::EXECUTABLE_REGISTRATION,
                        'from' => $this->generateUrl('asset', ['id' => $id, '_fragment' => 'asset-title'] + $context),
                    ]) : null,
                'findings' => $this->generateUrl('findings', $findingsParameters),
                'advisories' => $this->generateUrl('findings', $findingsParameters + ['view' => 'advisories']),
                'scan_history' => (int) $summary['has_history']
                    ? $this->generateUrl('findings', $findingsParameters + ['observation' => 'absent']) : null,
            ],
        ], $csrf);
    }

    #[Route('/assets/{id}/sbom', name: 'sbom', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function sbom(string $id): Response
    {
        $sbom = $this->inventory->get($id)['data']['sbom'] ?? throw $this->createNotFoundException();

        return new Response(Store::json($sbom), headers: [
            'Content-Type' => 'application/vnd.cyclonedx+json',
            'Content-Disposition' => 'attachment; filename="patchrocket-sbom.json"',
        ]);
    }

    #[Route('/findings', name: 'findings', methods: ['GET'])]
    public function findingsPage(Request $request, PreactPage $preact): Response
    {
        $filters = self::findingFilters($request);
        ['asset' => $asset, 'view' => $view, 'page' => $page] = $filters;
        $size = self::FINDINGS_PAGE_SIZE;
        $selected = $request->query->all()['locate_finding'] ?? null;
        if ('findings' === $view && is_string($selected) && preg_match('/^[a-f0-9]{64}$/D', $selected)) {
            ['selectedPage' => $selectedPage] = $this->findings($size, filters: $filters, selectedId: $selected);
            $parameters = $request->query->all();
            unset($parameters['locate_finding'], $parameters['page']);
            if (null === $selectedPage) {
                $parameters = ['finding_id' => $selected, 'observation' => 'all']
                    + array_intersect_key($parameters, array_flip(['fleet_from', 'finding_from', 'group_from']));
            } elseif ($selectedPage > 1) {
                $parameters['page'] = $selectedPage;
            }
            $parameters['_fragment'] = 'finding-result-'.$selected;

            return $this->redirectToRoute('findings', $parameters);
        }
        $offset = ($page - 1) * $size;
        ['rows' => $findings, 'total' => $matchCount] = $this->findings($size, $offset, $filters, countMatches: true);
        $lastPage = intdiv(max(0, $matchCount - 1), $size) + 1;
        if ('findings' === $view) {
            $findings = $this->findingTableRows($findings);
        } elseif ('advisories' === $view) {
            $findings = array_map(static fn (array $row): array => $row + ['group_id' => hash('sha256', (string) $row['advisory'])], $findings);
        }
        $restrictedAsset = $asset ? $this->store->row('SELECT name FROM assets WHERE id = ?', [$asset]) : null;
        $assetReturn = $asset ? DashboardListContext::assetDetail($request->query->all()['from'] ?? null,
            [DashboardListContext::ASSET_VULNERABILITIES_SECTION]) : null;
        $fleetReturn = DashboardListContext::parameters($request, DashboardListContext::FLEET, 'fleet_from')['fleet_from'] ?? null;
        $findingFrom = $request->query->all()['finding_from'] ?? null;
        $findingReturn = null !== DashboardListContext::findingDetailId($findingFrom, DashboardListContext::FINDING_ADVISORY_LINK)
            ? $findingFrom : null;
        $groupReturn = DashboardListContext::findingGroup($request);

        return $preact->render('findings', $filters + compact('findings', 'assetReturn', 'fleetReturn', 'findingReturn', 'groupReturn', 'lastPage', 'offset',
            'matchCount', 'restrictedAsset'));
    }

    #[Route('/api/findings/group-page', name: 'finding_group_page', methods: ['GET'])]
    public function findingGroupPage(Request $request): JsonResponse
    {
        $filters = self::findingFilters($request);
        $prefix = match ($filters['view']) {
            'advisories' => 'advisory-result-',
            'assets' => 'affected-asset-result-',
            default => null,
        };
        $group = $request->query->all()['group'] ?? null;
        if (null === $prefix || !is_string($group) || !preg_match('/^'.$prefix.'([a-f0-9]{64})$/D', $group, $match)) {
            return $this->json(['error' => 'Choose an advisory or affected asset group.'], Response::HTTP_BAD_REQUEST);
        }

        $result = $this->findings(self::FINDINGS_PAGE_SIZE, filters: $filters, selectedId: $match[1]);

        return $this->json(['page' => $result['selectedPage']]);
    }

    private static function findingFilters(Request $request): array
    {
        $severity = $request->query->getString('severity');
        $findingId = strtolower($request->query->getString('finding_id'));
        $findingId = preg_match('/^[a-f0-9]{64}$/D', $findingId) ? $findingId : '';
        $observation = $request->query->getString('observation');
        if (!in_array($observation, ['detected', 'absent', 'all'], true)) {
            $observation = $request->query->getBoolean('history') ? 'all' : 'detected';
        }
        $asset = $request->query->getString('asset');
        $exactAsset = '' !== $asset && $request->query->getBoolean('asset_exact');
        $assetName = trim($request->query->getString('asset_name'));
        $fix = $request->query->getBoolean('fix');
        $page = max(1, min(intdiv(PHP_INT_MAX, self::FINDINGS_PAGE_SIZE), $request->query->getInt('page', 1)));
        $advisory = strtoupper(trim($request->query->getString('advisory')));
        $package = trim($request->query->getString('package'));
        $ecosystem = trim($request->query->getString('ecosystem'));
        $scanTarget = trim($request->query->getString('target'));
        $runtime = $request->query->getString('runtime');
        $runtime = in_array($runtime, ['running', 'registry-only'], true) ? $runtime : '';
        $view = $request->query->getString('view');
        if ('' !== $findingId || ('advisories' !== $view && !('assets' === $view && '' !== $advisory))) {
            $view = 'findings';
        }

        return compact('severity', 'observation', 'asset', 'exactAsset', 'assetName', 'fix', 'page', 'advisory', 'package', 'ecosystem',
            'scanTarget', 'runtime', 'view', 'findingId');
    }

    #[Route('/findings/{id}', name: 'finding', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function finding(
        string $id,
        Request $request,
        PreactPage $preact,
        \Symfony\Component\Security\Csrf\CsrfTokenManagerInterface $tokens,
        VmPackageDashboard $packages,
        FindingHistory $history,
    ): Response {
        $context = DashboardListContext::finding($request);
        $finding = $this->findingRecord($id);

        $links = $this->inventory->links($finding['asset_id']);
        $asset = $this->assetWithScanState($finding['asset_id']);
        $parameters = ['id' => $id] + $context;
        $sourceUrl = $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_RELATED_SOURCE_SECTION]);
        $sourceFindings = [];
        foreach ($links as $link) {
            if (!in_array($link['kind'], ['BUILT_FROM', 'BUILD_SOURCE'], true) || 'repository' !== $link['asset_kind']) {
                continue;
            }
            foreach ($this->store->rows('SELECT * FROM findings WHERE asset_id = ? AND active = 1', [$link['id']]) as $source) {
                $keys = ['advisory', 'package', 'version'];
                if (array_intersect_key($source['data'], array_flip($keys)) == array_intersect_key($finding['data'], array_flip($keys))) {
                    [$anchor, $origin] = self::findingSourceTarget($sourceUrl, ['finding', $source['id']]);
                    $sourceFindings[$source['id']] = [
                        'url' => $this->generateUrl('finding', [
                            'id' => $source['id'], 'from' => $origin, '_fragment' => DashboardListContext::FINDING_DETAILS_SECTION,
                        ]),
                        'name' => $link['name'], 'anchor' => $anchor,
                    ];
                }
            }
        }

        $role = $request->attributes->get('_dashboard_role', 'admin');
        $preparation = 'viewer' !== $role ? $this->preparation->form($finding, $asset) : null;
        $csrf = [];
        $form = null;
        if ($preparation) {
            $form = self::detailFields($preparation, ['strategy', 'error', 'overlay', 'fixed']);
            if (isset($preparation['strategy'])) {
                $form['action'] = $this->generateUrl('prepare', ['id' => $id] + $context);
                $form['token_scope'] = 'prepare-'.$id;
                $form['token_url'] = $this->generateUrl('api_finding_prepare_token', ['id' => $id]);
                $csrf['prepare'] = $tokens->getToken($form['token_scope'])->getValue();
            }
            if (isset($preparation['repository'])) {
                $repository = $preparation['repository'];
                $connection = $preparation['connection'] ?? null;
                $form += [
                    'repository' => ['name' => $repository['name'], 'url' => $this->assetDetailUrl($repository['id'])],
                    'source' => self::detailFields($preparation['source'] ?? [], ['namespace', 'deployment', 'container', 'file', 'dockerfile']),
                    'connection' => 'admin' === $role ? [
                        'url' => $this->generateUrl('frontend_dashboard', ['view' => 'repositories', 'edit' => $connection['id'] ?? 'new']
                            + ($connection ? [] : ['patch_finding' => $id])),
                        'label' => $connection ? 'Edit the repository connection' : 'Add a repository connection',
                    ] : null,
                ];
            }
        }
        $repositories = array_filter($links, static fn (array $link): bool => 'repository' === $link['asset_kind']
            && in_array($link['kind'], ['BUILT_FROM', 'ASSOCIATED_SOURCE'], true));

        $session = $request->hasSession() ? $request->getSession() : null;
        $draft = $session?->get(self::PREPARATION_DRAFT);
        if (($draft['finding'] ?? null) === $id) {
            $session->remove(self::PREPARATION_DRAFT);
            if (in_array($form['strategy'] ?? null, ['docker-base', 'iac-image'], true)) {
                $form['draft'] = $draft;
            } else {
                $this->addFlash('error', $draft['error']);
            }
        }

        $runtime = 'image' === $asset['kind'] ? $this->inventory->imageRuntime($asset) + ['registry' => 'registry' === ($asset['data']['origin'] ?? null)] : null;
        $scan = self::scanEvidence($asset);
        $detailUrl = $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_DETAILS_SECTION]);
        $runtimeUrl = ($runtime['running'] ?? 0) > 0 ? $this->generateUrl('assets', [
            'running_image' => $asset['id'],
            'from' => $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_RUNTIME_LINK]),
            '_fragment' => 'asset-results',
        ]) : null;
        $buildSourceUrl = $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_BUILD_SOURCE_SECTION]);
        $deploymentSourceUrl = $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_DEPLOYMENT_SOURCE_SECTION]);
        $assetParameters = ['id' => $asset['id'], 'from' => $detailUrl];
        $back = $context['from'] ?? $this->generateUrl('findings');
        $backSource = DashboardListContext::findingSource($back);
        $advisoryParameters = [
            'advisory' => $finding['data']['advisory'], 'view' => 'assets', '_fragment' => 'vulnerability-results',
            'finding_from' => $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::FINDING_ADVISORY_LINK]),
        ];
        if (!$finding['active']) {
            $advisoryParameters['observation'] = 'all';
        }

        return $preact->render('finding', [
            'title' => $finding['data']['advisory'],
            'finding' => ['asset_url' => $this->generateUrl('asset', $assetParameters + ['_fragment' => 'asset-title'])]
                + $this->detailFinding($finding, true),
            'review' => $this->findingReview($id, $context['from'] ?? null),
            'runtime' => $runtime,
            'cleanup_url' => 'admin' === $role && $runtime && 0 === $runtime['running']
                ? $this->generateUrl('settings_registry_cleanup', ['asset' => $asset['id'], 'from' => $detailUrl, '_fragment' => 'cleanup-artifact']) : null,
            'package_update_url' => 'admin' === $request->attributes->get('_dashboard_role')
                ? $packages->fromFinding($asset, $finding, $detailUrl) : null,
            'scan' => $scan,
            'urls' => [
                'back' => $back,
                'back_label' => match (true) {
                    DashboardListContext::OVERVIEW === parse_url($back, PHP_URL_PATH) => 'Overview',
                    null !== DashboardListContext::assetFinding($back) => 'Asset vulnerabilities',
                    null !== $backSource => $backSource['label'],
                    null !== DashboardListContext::remediationDetail($back, DashboardListContext::REMEDIATION_ORIGINAL_FINDING_LINK) => 'Remediation plan',
                    default => 'Vulnerabilities',
                },
                'advisory' => $this->generateUrl('findings', $advisoryParameters),
                'history' => $this->findingHistoryUrl($parameters),
                'history_api' => $this->generateUrl('api_finding_history', ['id' => $id]),
                'runtime' => $runtimeUrl,
                'asset_scan' => 'failed' === $scan['scan_state']
                    ? $this->generateUrl('asset', $assetParameters + ['_fragment' => 'scan-failure']) : null,
            ],
            'repositories' => array_values(array_map(fn (array $link): array => $this->detailAssetLink($link, $sourceUrl), $repositories)),
            'source_findings' => array_values($sourceFindings),
            'build_sources' => $this->detailBuildSources($asset['data'], $buildSourceUrl),
            'delivery_sources' => $this->detailDeliverySources($asset, $deploymentSourceUrl),
            'preparation' => $form,
            'history' => $this->findingHistoryPage($history, $finding, $asset, $request, $parameters),
        ], $csrf);
    }

    #[Route('/api/findings/{id}/history', name: 'api_finding_history', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function findingHistory(string $id, Request $request, FindingHistory $history): JsonResponse
    {
        $finding = $this->findingRecord($id);
        $asset = $this->inventory->get($finding['asset_id']) ?? throw $this->createNotFoundException();
        $parameters = ['id' => $id] + DashboardListContext::finding($request);

        return new JsonResponse($this->findingHistoryPage($history, $finding, $asset, $request, $parameters),
            headers: ['Cache-Control' => 'private, no-store']);
    }

    private function findingRecord(string $id): array
    {
        return $this->store->row(
            'SELECT f.*, a.name AS asset_name, a.kind AS asset_kind FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.id = ?',
            [$id],
        ) ?? throw $this->createNotFoundException();
    }

    private function findingHistoryPage(FindingHistory $history, array $finding, array $asset, Request $request, array $parameters): array
    {
        $filters = DashboardListContext::findingHistoryFilters($request);
        $attempt = $request->query->all()['attempt'] ?? null;
        $attempt = is_string($attempt) && preg_match('/^[a-f0-9]{24}$/D', $attempt) ? $attempt : '';
        $view = $history->page($finding, $asset, $filters['history_q'] ?? '', $filters['history_page'] ?? 1, $attempt);
        $origin = $this->findingHistoryUrl($parameters + array_filter([
            'history_q' => $view['search'], 'history_page' => $view['page'] > 1 ? $view['page'] : null,
        ], static fn (mixed $value): bool => null !== $value && '' !== $value));
        foreach ($view['rows'] as &$row) {
            $row['url'] = $this->generateUrl('change', ['id' => $row['id'], 'from' => $origin]);
        }
        unset($row);

        return $view;
    }

    private function findingReview(string $id, ?string $from): ?array
    {
        if (null === $from) {
            return null;
        }
        $path = parse_url($from, PHP_URL_PATH);
        $assetPreview = null !== DashboardListContext::assetFinding($from);
        $prefix = $assetPreview ? DashboardListContext::ASSET_FINDING_PREFIX : DashboardListContext::FINDING_RESULT_PREFIX;
        if ($prefix.$id !== parse_url($from, PHP_URL_FRAGMENT)) {
            return null;
        }

        $list = '/findings' === $path;
        $filters = $assetPreview ? ['asset' => substr($path, strlen('/assets/'))] : [];
        $source = null;
        if ($list) {
            try {
                $source = Request::create($from);
                $filters = self::findingFilters($source);
            } catch (BadRequestException) {
                return null;
            }
            if ('findings' !== $filters['view']) {
                return null;
            }
        }
        [$size, $label, $scope] = match (true) {
            $list => [self::FINDINGS_PAGE_SIZE, 'Vulnerability results', null],
            $assetPreview => [self::ASSET_FINDINGS_PREVIEW_LIMIT, 'Asset vulnerability preview', 'in asset preview'],
            default => [self::PRIORITY_FINDINGS_LIMIT, 'Priority findings', 'on Overview'],
        };
        $page = $filters['page'] ?? 1;
        $pageStart = ($page - 1) * $size;
        // Include one row on each side of the current page for links across the boundary.
        $offset = max(0, $pageStart - 1);
        $limit = $list ? $size + ($pageStart - $offset) + 1 : $size;
        ['rows' => $rows, 'total' => $total] = $this->findings($limit, $offset, $filters, countMatches: $list);
        $current = array_search($id, array_column($rows, 'id'), true);
        if (false === $current || $offset + $current < $pageStart || $offset + $current >= $pageStart + $size || count($rows) < 2) {
            return null;
        }

        $review = ['label' => $label, 'scope' => $scope, 'position' => $offset + $current + 1, 'total' => $total ?? count($rows)];
        $origin = explode('#', $from, 2)[0];
        foreach (['previous' => $current - 1, 'next' => $current + 1] as $direction => $index) {
            if (!isset($rows[$index])) {
                continue;
            }
            $target = $origin;
            $targetPage = intdiv($offset + $index, $size) + 1;
            if ($source && $targetPage !== $page) {
                $query = $source->query->all();
                unset($query['page']);
                if ($targetPage > 1) {
                    $query['page'] = $targetPage;
                }
                $target = $path.($query ? '?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986) : '');
            }
            $nextId = $rows[$index]['id'];
            $target = DashboardReturnPath::validate($target.'#'.$prefix.$nextId);
            if (null !== $target) {
                $review[$direction] = $this->generateUrl('finding', ['id' => $nextId, 'from' => $target,
                    '_fragment' => DashboardListContext::FINDING_DETAILS_SECTION]);
            }
        }

        return isset($review['previous']) || isset($review['next']) ? $review : null;
    }

    #[Route('/api/findings/{id}/prepare-token', name: 'api_finding_prepare_token', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function preparationToken(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        if (false === $this->store->db->fetchOne('SELECT 1 FROM findings WHERE id = ?', [$id])) {
            throw $this->createNotFoundException();
        }
        $purpose = 'prepare-'.$id;

        return new JsonResponse([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/findings/{id}/prepare', name: 'prepare', requirements: ['id' => '[a-f0-9]{64}'], methods: ['POST'])]
    public function prepare(string $id, Request $request): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('prepare-'.$id, $fields->getString('_token'))) {
            if ($json) {
                return new JsonResponse(['error' => 'Your preparation form expired. Try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }
        $context = DashboardListContext::finding($request);
        $input = [
            'base' => $fields->getString('base'), 'credential' => $fields->getString('credential'),
            'current' => $fields->getString('current'), 'fixed' => $fields->getString('fixed'),
        ];
        try {
            $change = $this->preparation->start($id, $input);
            $redirect = $this->generateUrl('change', [
                'id' => $change, 'from' => $this->findingHistoryUrl(['id' => $id] + $context),
            ]);

            return $json ? new JsonResponse(['redirect' => $redirect]) : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
        } catch (\DomainException $error) {
            $problem = ['error' => $error->getMessage(), 'field' => $error instanceof RemediationFieldError ? $error->field : null];
            if ($json) {
                return new JsonResponse($problem, Response::HTTP_UNPROCESSABLE_ENTITY);
            }
            if ($fields->has('base') && $request->hasSession()) {
                $request->getSession()->set(self::PREPARATION_DRAFT, $problem + ['finding' => $id, 'values' => [
                    'base' => substr($input['base'], 0, 101),
                    'current' => substr($input['current'], 0, 512),
                    'fixed' => substr($input['fixed'], 0, 512),
                ]]);
                $context['_fragment'] = 'prepare-patch';
            } else {
                $this->addFlash('error', $problem['error']);
            }

            return $this->redirectToRoute('finding', ['id' => $id] + $context, Response::HTTP_SEE_OTHER);
        }
    }

    private function findingHistoryUrl(array $parameters): string
    {
        return $this->generateUrl('finding', $parameters + ['_fragment' => DashboardListContext::REMEDIATION_HISTORY_SECTION]);
    }

    #[Route('/remediations', name: 'changes', methods: ['GET'])]
    public function remediations(PreactPage $preact): Response
    {
        return $preact->render('remediations');
    }

    #[Route('/remediations/{id}', name: 'change', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    #[Route('/api/remediations/{id}', name: 'api_remediation_detail', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function change(
        string $id,
        ReleaseTracking $tracking,
        Connections $connections,
        ApprovalPolicy $approvalPolicy,
        IndependentVerification $independentVerification,
        DashboardPullRequests $pullRequests,
        JenkinsConnections $jenkinsConnections,
        OperatorSettings $operatorSettings,
        Request $request,
        PreactPage $preact,
        \Symfony\Component\Security\Csrf\CsrfTokenManagerInterface $tokens,
    ): Response {
        $asJson = 'api_remediation_detail' === $request->attributes->get('_route');
        $query = $this->dashboardStatuses->query('c.*, r.data AS release_tracking_data,
            r.next_at AS release_tracking_next_at, r.lease_until AS release_tracking_lease_until,
            (SELECT COUNT(*) FROM audit a WHERE a.change_id = c.id) AS event_count');
        $change = $this->store->row($query.' WHERE c.id = ?', [$id]) ?? throw $this->createNotFoundException();
        $role = $request->attributes->get('_dashboard_role', 'admin');
        $admin = 'admin' === $role;
        $operator = 'viewer' !== $role;
        $data = $change['data'];
        $plan = $data['plan'] ?? [];
        $binary = 'standalone-binary' === $change['strategy'];
        $iac = 'iac-image' === $change['strategy'];
        $dockerBase = 'docker-base' === $change['strategy'];
        $evidence = self::detailFields([
            'upstream_image' => $iac ? ($data['image_verification']['image'] ?? null) : null,
            'verification_image_id' => $dockerBase ? ($data['image_verification']['digest'] ?? null) : null,
        ] + $data, ['revision', 'patch_sha256', 'lock_sha256', 'candidate_image', 'binary_sha256', 'upstream_image', 'verification_image_id']);
        $planDetails = $binary
            ? self::detailFields($plan, ['candidate']) + self::detailFields($plan['profile'] ?? [], ['path', 'digest'])
            : self::detailFields($plan + [
                'package' => $data['finding']['package'] ?? null,
                'dockerfile' => $dockerBase && is_array($plan['files'] ?? null) ? ($plan['files'][0] ?? null) : null,
            ], ['package', 'installed', 'current', 'fixed', 'namespace', 'deployment', 'container', 'file', 'dockerfile']);
        $status = $change['status'];
        $candidate = new Change($id, $change['strategy'], $status, $data);
        $verification = 'awaiting_approval' === $status ? $independentVerification->status($candidate) : null;
        $hold = 'awaiting_approval' === $status ? $approvalPolicy->hold($candidate) : null;
        $context = DashboardListContext::remediation($request);
        $nextAttempt = 'failed' === $status ? $this->changes->nextAttempt($id) : null;
        $releaseData = isset($change['release_tracking_data'])
            ? json_decode($change['release_tracking_data'], true, flags: JSON_THROW_ON_ERROR) : null;
        $hasTracker = null !== $releaseData;
        $releaseProgress = $hasTracker ? self::detailReleaseProgress(
            $releaseData['result'] ?? [], (int) $change['release_tracking_next_at'], (int) $change['release_tracking_lease_until'],
        ) : null;
        $releaseSettings = $releaseData['settings'] ?? null;
        $releaseSettingsVersion = $operator ? ReleaseTracking::settingsVersion($releaseSettings) : null;
        $jenkins = $operator && $hasTracker ? self::releaseJenkins($releaseSettings ?? [], $jenkinsConnections) : null;
        $delivery = $operator && $hasTracker ? self::releaseDelivery($releaseData, $connections) : null;
        $registry = null;
        if ($operator && 'Harbor' === ($releaseData['result']['stage'] ?? null) && is_string($data['observed_image'] ?? null)) {
            $repository = explode('@', $data['observed_image'], 2)[0];
            $host = HarborRelease::repositoryHost($repository);
            if (null !== $host) {
                $registry = ['host' => $host, 'configured' => (bool) $operatorSettings->registryReference($host)];
            }
        }
        $hasRollout = $iac && in_array($status, ['approved', 'deployed'], true);
        $rolloutOptions = $hasRollout && $operator ? $connections->all() : null;
        $publication = $tracking->publication($change);
        $releaseConnections = $operator && $publication ? ($rolloutOptions ?? $connections->all()) : null;
        $releaseOptions = null === $releaseConnections ? [] : [
            'repositories' => $this->detailConnectionOptions($releaseConnections, 'repository', static fn (array $scope): bool =>
                'infrastructure' === ($scope['role'] ?? null)),
            'clusters' => $this->detailConnectionOptions($releaseConnections, 'cluster'),
        ];
        $rolloutConnectionIds = $admin && null !== $rolloutOptions
            ? array_fill_keys(array_column($this->detailConnectionOptions($rolloutOptions, 'cluster'), 'id'), true) : [];
        $rolloutImage = $data['image_verification']['image'] ?? null;
        $rolloutNamespace = $plan['namespace'] ?? '';
        $rolloutClusters = null !== $rolloutOptions && 'approved' === $status && $rolloutImage
            ? $this->detailConnectionOptions($rolloutOptions, 'cluster', static fn (array $scope): bool =>
                ($scope['target'] ?? null) === ($plan['context'] ?? null) && !empty($scope['credential'])
                && Connections::coversNamespace($scope, $rolloutNamespace))
            : null;
        $hasPullRequest = !$binary && in_array($status, ['awaiting_approval', 'approved', 'monitoring', 'deployed'], true);
        $pr = $hasPullRequest && $admin ? $pullRequests->publication($id) : null;
        $pullRequestRepositories = $hasPullRequest && $admin
            ? $pullRequests->repositoryOptions($candidate, $rolloutOptions ?? $releaseConnections ?? $connections->byKind('repository'), $pr) : null;
        $progress = [
            'active' => in_array($status, DashboardStatuses::GROUPS['active'], true)
                || in_array($verification['state'] ?? null, ['queued', 'running'], true)
                || null !== ($releaseProgress['next_at'] ?? null)
                || ($releaseProgress['checking'] ?? false),
            'version' => hash('sha256', Store::json([
                $id, $role, $context, $change['display_status'], $change['event_count'],
                $evidence, $planDetails, $verification, $hold, $nextAttempt, $jenkins, $registry, $delivery,
                $releaseProgress, $releaseSettingsVersion, $releaseOptions, $rolloutConnectionIds, $rolloutClusters, $pullRequestRepositories,
            ])),
        ];
        $responseHeaders = ['Cache-Control' => 'private, no-store'];
        if ($asJson && $progress['version'] === $request->query->getString('known')) {
            return new JsonResponse(['unchanged' => true], headers: $responseHeaders);
        }

        $events = $this->store->rows('SELECT * FROM audit WHERE change_id = ? ORDER BY id', [$id]);
        $params = ['id' => $id] + $context;
        $findingHistory = DashboardListContext::findingHistory($context['from'] ?? null);
        $back = $findingHistory
            ? $this->findingHistoryUrl($findingHistory + ['attempt' => $id])
            : ($context['from'] ?? $this->generateUrl('changes'));
        $executableHistory = $binary && is_string($plan['binary'] ?? null)
            && in_array(parse_url($back, PHP_URL_PATH), DashboardListContext::REMEDIATIONS, true)
            && (Request::create($back)->query->all()['executable'] ?? null) === $plan['binary'];
        $queueSection = DashboardListContext::QUEUE === parse_url($back, PHP_URL_PATH)
            ? explode('/', parse_url($back, PHP_URL_FRAGMENT) ?? '', 2)[0] : null;
        $urls = [
            'back' => $back,
            'back_to_release_trackers' => DashboardListContext::RELEASE_TRACKERS_SECTION === $queueSection,
            'back_label' => match (true) {
                null !== $findingHistory => 'Finding history',
                DashboardListContext::OVERVIEW === parse_url($back, PHP_URL_PATH) => 'Overview',
                DashboardListContext::RELEASE_TRACKERS_SECTION === $queueSection => 'Release trackers',
                DashboardListContext::REMEDIATION_JOBS_SECTION === $queueSection => 'Remediation jobs',
                null !== DashboardListContext::rolloutSchedule($back) => 'Docker rollout schedules',
                null !== DashboardListContext::executables($back) => 'Standalone executables',
                $executableHistory => 'Executable build attempts',
                default => 'Remediations',
            },
            'refresh' => $this->generateUrl('change', $params),
            'progress' => $this->generateUrl('api_remediation_detail', $params),
        ];
        $csrf = [];
        $actions = [];
        $form = function (string $key, string $route, string $purpose) use (&$actions, &$csrf, $params, $id, $tokens): void {
            $actions[$key] = $this->generateUrl($route, $params);
            $csrf[$key] = $tokens->getToken($purpose.'-'.$id)->getValue();
        };

        $approval = null;
        if ('awaiting_approval' === $status) {
            $approval = [
                'hold' => $hold['reason'] ?? null,
                'verification' => $verification,
                'requires_administrator' => !$admin,
                'policy_url' => $admin && $hold ? $this->generateUrl('settings_policy', [
                    'repository' => $change['asset_id'], '_fragment' => DashboardListContext::APPROVAL_POLICY_EDITOR_SECTION,
                    'from' => $this->generateUrl('change', $params + ['_fragment' => DashboardListContext::APPROVAL_SECTION]),
                ]) : null,
            ];
            if ($admin && !$hold) {
                $form('approve', 'approve', 'approve');
            }
            if ($admin && ApprovalPolicy::INDEPENDENT_VERIFICATION_REQUIRED === ($hold['code'] ?? null)
                && !in_array($verification['state'] ?? null, ['queued', 'running'], true)
                && IndependentVerification::hasCandidate($candidate)) {
                $form('independent_verification', 'change_independent_verification', 'independent-verification');
            }
            if (isset($actions['approve']) || isset($actions['independent_verification'])) {
                $urls['approval_tokens'] = $this->generateUrl('api_approval_tokens', ['id' => $id]);
            }
        }
        if ($operator && $binary && in_array($status, ['approved', 'deployed'], true)) {
            $urls['binary_download'] = $this->generateUrl('binary_download', $params);
            if ('approved' === $status) {
                $form('binary_verify', 'binary_verify', 'verify-binary');
                $urls['binary_verify_token'] = $this->generateUrl('api_binary_verify_token', ['id' => $id]);
            }
        }
        if ($operator && isset($data['patch'])) {
            $urls['patch'] = $this->generateUrl('patch', $params);
        }
        if ($nextAttempt) {
            $urls['next_attempt'] = $this->generateUrl('change', ['id' => $nextAttempt, '_fragment' => 'execution-timeline']
                + DashboardListContext::withPreparationJobAttempt($context, $nextAttempt));
        } elseif ($operator && Changes::canRetryPreparation($candidate)) {
            $form('retry_preparation', 'change_retry_preparation', 'retry-preparation');
            $urls['retry_preparation_token'] = $this->generateUrl('api_retry_preparation_token', ['id' => $id]);
        }
        if ($admin && 'monitoring' === $status && !empty($data['candidate_image'])) {
            $urls['rollout_schedule'] = $this->generateUrl('settings_policy', [
                'rollout_change' => $id, '_fragment' => 'rollout-schedules', 'from' => $urls['refresh'].'#execution-timeline',
            ]);
        }
        if (is_string($data['retry_of'] ?? null) && preg_match('/^[a-f0-9]{24}$/D', $data['retry_of'])) {
            $urls['previous_attempt'] = $this->generateUrl('change', [
                'id' => $data['retry_of'], 'events' => 'failed', '_fragment' => 'execution-timeline',
            ] + DashboardListContext::withPreparationJobAttempt($context, $data['retry_of']));
        }

        $rollout = null;
        if ($hasRollout) {
            $observation = $attempt = null;
            foreach ($events as $event) {
                if ('rollout_check' === $event['kind']) {
                    $observation = $attempt = $event;
                } elseif ('rollout_unavailable' === $event['kind']) {
                    $attempt = $event;
                }
            }
            $result = $observation['data'] ?? [];
            $unavailable = 'rollout_unavailable' === ($attempt['kind'] ?? null);
            $rollout = [
                'verified' => 'deployed' === $status,
                'image' => $rolloutImage,
                'observation' => $observation ? self::detailFields($result, ['passed', 'ready', 'expected', 'log'])
                    + $this->rolloutConnectionDetails($result, $operator, $rolloutConnectionIds) + [
                    'issues' => self::detailStrings($result['issues'] ?? []),
                    'created_at' => $observation['created_at'],
                    'url' => $urls['refresh'].'#execution-event-'.$observation['id'],
                ] : null,
                'unavailable' => $unavailable ? $this->rolloutConnectionDetails($attempt['data'], $operator, $rolloutConnectionIds) + [
                    'note' => $attempt['data']['note'], 'created_at' => $attempt['created_at'],
                    'url' => $urls['refresh'].'#execution-event-'.$attempt['id'],
                ] : null,
            ];
            if (null !== $rolloutClusters) {
                $lastConnection = $attempt['data']['connection'] ?? '';
                $selected = in_array($lastConnection, array_column($rolloutClusters, 'id'), true) ? $lastConnection : '';
                $rollout += [
                    'clusters' => $rolloutClusters,
                    'connection' => $selected,
                    'settings_url' => $admin ? $this->generateUrl('frontend_dashboard', [
                        'view' => 'clusters', 'from' => $urls['refresh'].'#'.DashboardListContext::RUNTIME_VERIFICATION_SECTION,
                    ]) : null,
                ];
                if ($rolloutClusters) {
                    $form('verify_iac', 'verify_iac', 'verify-iac');
                    $urls['verify_iac_token'] = $this->generateUrl('api_verify_iac_token', ['id' => $id]);
                }
            }
        }

        $pullRequest = null;
        if ($hasPullRequest) {
            if (!$admin) {
                $pr = $pullRequests->publication($id);
            }
            $prUrl = self::detailExternalUrl($pr['url'] ?? null);
            $mergeEvidence = $pr ? DashboardPullRequests::mergeEvidence($pr, $events) : null;
            if ($mergeEvidence) {
                $mergeEvidence['url'] = $urls['refresh'].'#execution-event-'.$mergeEvidence['id'];
            }
            $pullRequest = $prUrl || $admin ? [
                'url' => $prUrl,
                'merge_evidence' => $mergeEvidence,
                'runtime_verified' => in_array($change['display_status'], ['deployed', 'release_verified'], true),
                'runtime_url' => $publication || $hasTracker ? '#release-tracking' : ($rollout ? '#runtime-verification' : null),
            ] : null;
            if (null !== $pullRequestRepositories) {
                if ($mergeEvidence['confirmed'] ?? false) {
                    $pullRequestRepositories['merge_repositories'] = [];
                }
                if ($pullRequestRepositories['publish_repositories'] || $pullRequestRepositories['merge_repositories']) {
                    $form('pull_request', 'change_pull_request', 'pull-request');
                    $urls['pull_request_token'] = $this->generateUrl('api_pull_request_token', ['id' => $id]);
                }
                $pullRequest += [
                    'base' => $data['base_branch'] ?? 'main',
                    'awaiting_approval' => 'awaiting_approval' === $status,
                    'iac' => $iac,
                    'bitbucket' => str_starts_with($data['source_url'] ?? '', 'https://bitbucket.org/'),
                    'has_image_evidence' => !empty($data['image_verification']),
                    'settings_url' => $this->generateUrl('frontend_dashboard', [
                        'view' => 'repositories', 'from' => $urls['refresh'].'#'.DashboardListContext::PULL_REQUEST_SECTION,
                    ]),
                ] + $pullRequestRepositories;
            }
        }

        $release = null;
        if ($publication || $hasTracker) {
            $suggestions = null !== $releaseConnections && !$hasTracker ? $tracking->suggestedSettings($change, $releaseConnections) : [];
            $release = self::detailRelease($publication, $releaseSettings, $operator, $releaseOptions, $suggestions)
                + ['tracking' => $releaseProgress];
            if ($operator && $publication) {
                $release['settings_version'] = $releaseSettingsVersion;
            }
            if ($jenkins) {
                $release['jenkins'] = $jenkins;
            }
            if ($registry) {
                $release['registry'] = $registry;
            }
            if ($delivery) {
                $release['delivery'] = $delivery;
            }
            if ($admin && $publication) {
                $return = ['from' => $urls['refresh'].'#'.DashboardListContext::RELEASE_TRACKING_SECTION];
                $release['integrations_url'] = $this->generateUrl('settings_integrations', $return);
                if (isset($jenkins['server'])) {
                    $release['jenkins']['settings_url'] = $this->generateUrl('settings_integrations', $return + [
                        'jenkins' => $jenkins['server'], '_fragment' => 'jenkins',
                    ]);
                }
                if ($registry) {
                    $release['registry']['settings_url'] = $this->generateUrl('settings_integrations', $return + [
                        'registry' => $registry['host'], '_fragment' => 'harbor',
                    ]);
                }
                if ($delivery) {
                    $connection = $delivery['connection']['id'] ?? null;
                    $release['delivery']['connection_url'] = $this->generateUrl('frontend_dashboard', $return + [
                        'view' => 'repository' === $delivery['stage'] ? 'repositories' : 'clusters',
                    ] + ($connection ? ['edit' => $connection] : []));
                    if ('argo' === $delivery['stage'] && $connection) {
                        $release['delivery']['argo_url'] = $this->generateUrl('settings_integrations', $return + [
                            'argo_cluster' => $connection, '_fragment' => DashboardListContext::ARGO_SECTION,
                        ]);
                    }
                }
            }
            if ($operator) {
                $form('release_tracking', 'release_tracking', 'release-tracking');
                $urls['release_tracking_token'] = $this->generateUrl('api_release_tracking_token', ['id' => $id]);
                $session = !$asJson && $request->hasSession() ? $request->getSession() : null;
                if ($session instanceof FlashBagAwareSessionInterface) {
                    $release['notices'] = [
                        'success' => $session->getFlashBag()->get('release_tracking_success_'.$id),
                        'error' => $session->getFlashBag()->get('release_tracking_error_'.$id),
                    ];
                }
            }
        }

        $originalFinding = $change['finding_id'];
        $original = $binary ? $this->assetDetailUrl($plan['binary'] ?? null, DashboardListContext::executables($context['from'] ?? null))
            : (preg_match('/^[a-f0-9]{64}$/D', $originalFinding) && $originalFinding !== ($findingHistory['id'] ?? null)
                && false !== $this->store->db->fetchOne('SELECT 1 FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = ?', [$originalFinding])
                ? $this->generateUrl('finding', ['id' => $originalFinding, '_fragment' => DashboardListContext::FINDING_DETAILS_SECTION]) : null);
        $pageData = [
            'title' => $data['title'] ?? $data['finding']['advisory'] ?? substr($id, 0, 8),
            'change' => self::detailFields($change, ['id', 'strategy', 'display_status']),
            'progress' => $progress,
            'evidence' => $evidence,
            'plan' => $planDetails,
            'urls' => $urls + ['original' => $original],
            'actions' => $actions,
            'approval' => $approval,
            'rollout' => $rollout,
            'patch' => isset($urls['patch']) ? $data['patch'] : null,
            'pull_request' => $pullRequest,
            'release' => $release,
            'events' => array_map(fn (array $event): array => $this->detailEvent($event, $operator, $rolloutConnectionIds), $events),
        ];

        return $asJson
            ? new JsonResponse(['data' => $pageData, 'csrf' => (object) $csrf], headers: $responseHeaders)
            : $preact->render('change', $pageData, $csrf);
    }

    private function assetWithScanState(string $id): array
    {
        $scanState = DashboardScanEvidence::stateSql($this->store);
        $scheduleState = DashboardScanEvidence::scheduleStateSql(time());
        $failedAt = DashboardScanEvidence::attemptSql($this->store);
        $scheduleOutcome = $this->store->jsonText('s.data', 'outcome');
        $scheduleAttemptedAt = $this->store->jsonText('s.data', 'attempted_at');
        $scheduleFailureReason = $this->store->jsonText('s.data', 'failure_reason');

        return $this->store->row("SELECT a.*, $scanState AS scan_state, $failedAt AS failed_at,
                s.next_at AS schedule_next_at, s.interval_seconds AS schedule_interval_seconds, $scheduleState AS schedule_state,
                $scheduleOutcome AS schedule_outcome,
                $scheduleAttemptedAt AS schedule_attempted_at, $scheduleFailureReason AS schedule_failure_reason
            FROM assets a LEFT JOIN scan_schedules s ON s.id = a.id WHERE a.id = ?", [$id])
            ?? throw $this->createNotFoundException();
    }

    private function assetScanSettingsUrl(string $id, array $context, string $assetSection, string $settingsSection = 'recurring-scans'): string
    {
        return $this->generateUrl('settings_scanning', [
            'asset' => $id,
            'from' => $this->generateUrl('asset', ['id' => $id, '_fragment' => $assetSection] + $context),
            '_fragment' => $settingsSection,
        ]);
    }

    private static function scanEvidence(array $asset): array
    {
        return ['scan_state' => $asset['scan_state'], 'scan_attempted_at' => $asset['failed_at']]
            + self::detailFields($asset['data'], ['scan_source', 'scanned_at']);
    }

    private function detailFinding(array $finding, bool $full = false, ?string $assetPreview = null): array
    {
        $fields = $full ? [...self::FINDING_SUMMARY_FIELDS, 'title', 'cvss'] : self::FINDING_SUMMARY_FIELDS;

        $parameters = ['id' => $finding['id']];
        if (null !== $assetPreview) {
            $parameters['from'] = $assetPreview.'#'.DashboardListContext::ASSET_FINDING_PREFIX.$finding['id'];
        }

        return self::detailFields($finding, ['id', 'source', 'asset_name', 'last_seen']) + [
            'active' => (bool) $finding['active'],
            'details' => self::detailFields($finding['data'], $fields),
            'url' => $this->generateUrl('finding', $parameters),
            'asset_url' => $this->assetDetailUrl($finding['asset_id']),
        ] + ($full ? ['advisory_url' => self::detailExternalUrl($finding['data']['url'] ?? null)] : []);
    }

    private function detailAssetLink(array $link, ?string $from = null): array
    {
        return self::detailFields($link, ['name', 'asset_kind', 'kind', 'discovery', 'observed_at']) + (null === $from
            ? ['url' => $this->assetDetailUrl($link['id'])]
            : $this->detailSourceAsset($link['id'], $from, ['asset', $link['source_id'], $link['kind'], $link['target_id']]));
    }

    /** @return array{?string, ?string} */
    private static function findingSourceTarget(?string $from, array $identity): array
    {
        if (null === $from) {
            return [null, null];
        }
        $url = $from.'/'.hash('sha256', Store::json($identity));

        return [parse_url($url, PHP_URL_FRAGMENT) ?: null, DashboardReturnPath::validate($url) ?? $from];
    }

    private function detailSourceAsset(mixed $id, ?string $from, array $identity): array
    {
        [$anchor, $origin] = self::findingSourceTarget($from, $identity);

        return ['url' => $this->assetDetailUrl($id, $origin), 'anchor' => $anchor];
    }

    private function detailBuildSources(array $asset, ?string $from = null): array
    {
        $sources = [];
        foreach ($asset['build_sources'] ?? [] as $context => $source) {
            $repository = $source['repository'] ?? null;
            $identity = [$context, $repository, $source['dockerfile'] ?? null];
            $applications = [];
            foreach ($source['applications'] ?? [] as $id => $name) {
                $applications[] = ['name' => $name] + $this->detailSourceAsset($id, $from, [...$identity, 'application', $id]);
            }
            $sources[] = self::detailFields($source, ['repository_name', 'revision', 'dockerfile', 'jenkinsfile']) + [
                'context' => $context, 'applications' => $applications,
            ] + $this->detailSourceAsset($repository, $from, [...$identity, 'repository']);
        }

        return $sources;
    }

    private function detailDeliverySources(array $asset, ?string $from = null): array
    {
        $digest = $asset['data']['digest'] ?? '';
        if ('image' !== $asset['kind'] || '' === $digest) {
            return [];
        }
        $image = $this->store->jsonText('c.data', 'image');
        $running = $this->store->jsonText('c.data', 'running');
        $sources = [];
        foreach ($this->store->rows("SELECT DISTINCT app.id, app.name, app.data
            FROM assets c
            JOIN asset_links pc ON pc.target_id = c.id AND pc.kind = 'HOSTS'
            JOIN assets pod ON pod.id = pc.source_id AND pod.kind = 'pod'
            JOIN asset_links wp ON wp.target_id = pod.id AND wp.kind = 'HOSTS'
            JOIN assets workload ON workload.id = wp.source_id AND workload.kind = 'workload'
            JOIN asset_links wa ON wa.source_id = workload.id AND wa.kind = 'MANAGED_BY'
            JOIN assets app ON app.id = wa.target_id AND app.kind = 'argo-application'
            WHERE c.kind = 'container' AND $image = ? AND $running IN ('1', 'true')", [$digest]) as $app) {
            foreach ($app['data']['declarations'] ?? [] as $repoId => $declaration) {
                if (empty($declaration['file']) || !($repository = $this->inventory->get($repoId))) {
                    continue;
                }
                $charts = [];
                foreach ($declaration['sources'] ?? [] as $entry) {
                    if (!empty($entry['chart'])) {
                        $charts[] = self::detailFields($entry, ['chart', 'revision']);
                    }
                }
                $remote = ($repository['data']['canonical_url'] ?? '') ?: ($repository['data']['source_url'] ?? '');
                $revision = $declaration['infra_revision'] ?? '';
                $fileUrl = null;
                if (preg_match('~^(https://(bitbucket\.org|github\.com)/[\w.-]+/[\w.-]+)\.git$~D', $remote, $parts)
                    && preg_match('/^[a-f0-9]{40,64}$/D', $revision)) {
                    $path = implode('/', array_map(rawurlencode(...), explode('/', $declaration['file'])));
                    $fileUrl = $parts[1].('bitbucket.org' === $parts[2] ? '/src/' : '/blob/').$revision.'/'.$path;
                }
                $identity = [$app['id'], $repoId, $declaration['file']];
                $appLink = $this->detailSourceAsset($app['id'], $from, [...$identity, 'application']);
                $repoLink = $this->detailSourceAsset($repoId, $from, [...$identity, 'repository']);
                $sources[] = [
                    'application' => $app['name'], 'application_url' => $appLink['url'], 'application_anchor' => $appLink['anchor'],
                    'repository' => $repository['name'], 'repository_url' => $repoLink['url'], 'repository_anchor' => $repoLink['anchor'],
                    'file' => $declaration['file'], 'file_url' => $fileUrl, 'namespace' => $declaration['destination'],
                    'charts' => $charts,
                ];
            }
        }

        return $sources;
    }

    private function detailArgo(array $asset): array
    {
        $sources = static fn (array $entries): array => array_values(array_map(static fn (array $source): array =>
            self::detailFields($source, ['repository', 'ref', 'revision', 'synced_revision', 'chart', 'path', 'release', 'image_tag'])
            + ['values_files' => self::detailStrings($source['values_files'] ?? [])], $entries));
        $declarations = [];
        foreach ($asset['declarations'] ?? [] as $repository => $definition) {
            $declarations[] = self::detailFields($definition, ['file', 'infra_revision', 'destination', 'cluster']) + [
                'url' => $this->assetDetailUrl($repository), 'sources' => $sources($definition['sources'] ?? []),
            ];
        }
        $observation = $asset['observation'] ?? null;

        return self::detailFields($asset, ['context', 'namespace']) + [
            'declarations' => $declarations,
            'observation' => null === $observation ? null : self::detailFields($observation, ['observed_at', 'sync', 'health', 'destination'])
                + ['sources' => $sources($observation['sources'] ?? [])],
        ];
    }

    private static function detailReleaseProgress(array $result, int $next, int $leaseUntil): array
    {
        $checks = [];
        foreach ($result['checks'] ?? [] as $label => $evidence) {
            $checks[] = self::detailFields($evidence, ['detail', 'passed']) + [
                'label' => $label,
                'url' => self::detailExternalUrl($evidence['url'] ?? null),
                'issues' => self::detailStrings((array) ($evidence['issues'] ?? [])),
            ];
        }
        $now = time();
        return self::detailFields($result, ['status', 'note', 'stage', 'checked_at']) + [
            'next_at' => $next > 0 ? gmdate(DATE_ATOM, $next) : null,
            'due' => $next > 0 && $next <= $now,
            'checking' => $leaseUntil > $now,
            'checks' => $checks,
        ];
    }

    private static function detailRelease(?array $publication, ?array $settings, bool $operator, array $options, array $suggestions): array
    {
        $release = self::detailFields($publication ?? [], ['number']) + ['url' => self::detailExternalUrl($publication['url'] ?? null)];
        if ($operator && $publication) {
            $settings ??= $suggestions;
            $release += [
                'suggested_settings' => [] !== $suggestions,
                'settings' => self::detailFields($settings, [
                    'infra_connection', 'infra_branch', 'infra_file', 'cluster_connection',
                    'application', 'namespace', 'deployment', 'container',
                ]) + [
                    'bitbucket_credential' => self::detailCredential($settings['bitbucket_credential'] ?? null),
                    'jenkins_credential' => self::detailCredential($settings['jenkins_credential'] ?? null),
                    'jenkins_job' => self::detailExternalUrl($settings['jenkins_job'] ?? null),
                ],
            ] + $options;
        }

        return $release;
    }

    private static function releaseJenkins(array $settings, JenkinsConnections $connections): array
    {
        $job = $settings['jenkins_job'] ?? '';
        if (!is_string($job) || !JenkinsBuildStatus::validJob($job)) {
            return ['source' => 'job_required'];
        }
        if (!empty($settings['jenkins_credential'])) {
            return ['source' => 'override'];
        }
        $connection = $connections->connectionFor($job);

        return $connection ? ['source' => 'saved_server', 'server' => $connection['server']]
            : ['source' => 'server_required', 'server' => JenkinsBuildStatus::suggestedServer($job)];
    }

    private static function releaseDelivery(array $tracking, Connections $connections): ?array
    {
        $settings = $tracking['settings'] ?? [];
        $result = $tracking['result'] ?? [];
        if ('infra repository' === ($result['stage'] ?? null)) {
            $repository = $connections->get($settings['infra_connection'] ?? '');

            return [
                'stage' => 'repository',
                'connection' => 'repository' === ($repository['kind'] ?? null) ? self::detailFields($repository, ['id', 'name']) : null,
                'field' => ReleaseTracking::infrastructureSetupField($settings, $repository),
            ];
        }
        if ('Argo CD and Kubernetes' !== ($result['stage'] ?? null)) {
            return null;
        }
        $cluster = $connections->get($settings['cluster_connection'] ?? '');
        if ('cluster' !== ($cluster['kind'] ?? null)) {
            return ['stage' => 'argo', 'connection' => null, 'field' => 'cluster_connection'];
        }
        $scope = $cluster['data'];

        return [
            'stage' => 'argo', 'connection' => self::detailFields($cluster, ['id', 'name']),
            'configured_namespace' => $scope['argo_namespace'] ?? '',
            'checked_namespace' => $result['argo_application_namespace'] ?? null,
            'argo_access' => ReleaseTracking::argoCredentialSource($scope),
            'workload_access_required' => 'worker' !== ($scope['credential_mode'] ?? null) && empty($scope['credential']),
        ];
    }

    private function detailEvent(array $event, bool $operator, array $rolloutConnectionIds): array
    {
        $fields = match ($event['kind']) {
            'transition' => ['to', 'note'],
            'check' => ['label', 'passed', 'round', 'log'],
            'rollout_check' => ['label', 'passed', 'round', 'log', 'ready', 'expected'],
            'independent' => ['passed'],
            'merge', 'rollout_unavailable', 'binary_installation_unavailable' => ['note'],
            'release_tracking' => ['status', 'note'],
            'proposal' => ['provider', 'model', 'round', 'note'],
            default => [],
        };

        return self::detailFields($event, ['id', 'kind', 'created_at']) + [
            'details' => self::detailFields($event['data'], $fields) + match ($event['kind']) {
                'export' => ['url' => self::detailExternalUrl($event['data']['url'] ?? null)],
                'rollout_check' => ['issues' => self::detailStrings((array) ($event['data']['issues'] ?? []))]
                    + $this->rolloutConnectionDetails($event['data'], $operator, $rolloutConnectionIds),
                'rollout_unavailable' => $this->rolloutConnectionDetails($event['data'], $operator, $rolloutConnectionIds),
                default => [],
            },
        ];
    }

    private function rolloutConnectionDetails(array $evidence, bool $operator, array $rolloutConnectionIds): array
    {
        $details = $operator ? self::detailFields($evidence, ['connection', 'connection_name']) : [];
        $id = $details['connection'] ?? '';
        if (is_string($id) && isset($rolloutConnectionIds[$id])) {
            $details['connection_settings_url'] = $this->generateUrl('frontend_dashboard', ['view' => 'clusters', 'edit' => $id]);
        }

        return $details;
    }

    private function detailConnectionOptions(array $connections, string $kind, ?callable $matches = null): array
    {
        $options = [];
        foreach ($connections as $connection) {
            if ($kind === $connection['kind'] && (null === $matches || $matches($connection['data']))) {
                $options[] = ['id' => $connection['id'], 'name' => $connection['name']];
            }
        }

        return $options;
    }

    private function assetDetailUrl(mixed $id, ?string $from = null): ?string
    {
        $context = null === $from ? [] : ['from' => $from, '_fragment' => 'asset-title'];

        return is_string($id) && preg_match('/^[a-f0-9]{64}$/D', $id) ? $this->generateUrl('asset', ['id' => $id] + $context) : null;
    }

    private static function detailExternalUrl(mixed $url): ?string
    {
        if (!is_string($url) || !preg_match('~^https?://~i', $url) || preg_match('~[\x00-\x20\x7f\\\\]~', $url)) {
            return null;
        }
        $parts = parse_url($url);

        return !empty($parts['host']) && !isset($parts['user']) && !isset($parts['pass']) ? $url : null;
    }

    private static function detailCredential(mixed $reference): string
    {
        return is_string($reference) && \App\Secrets\SecretManagers::validReference($reference) ? $reference : '';
    }

    private static function detailFields(array $data, array $keys): array
    {
        return array_filter(array_intersect_key($data, array_flip($keys)), is_scalar(...));
    }

    private static function detailStrings(array $values): array
    {
        return array_values(array_filter($values, is_string(...)));
    }

    #[Route('/api/remediations/{id}/verify-iac-token', name: 'api_verify_iac_token', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function verifyIacToken(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        if ('iac-image' !== $this->changes->get($id)?->strategy) {
            throw $this->createNotFoundException();
        }
        $purpose = 'verify-iac-'.$id;

        return new JsonResponse([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/verify-iac', name: 'verify_iac', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function verifyIac(string $id, Request $request, Connections $connections, ConnectionCredentials $credentials, GitOps $gitOps): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'verify-iac-'.$id, $json)) {
            return $failure;
        }
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        $plan = $change->data['plan'] ?? [];
        $connectionId = $request->request->getString('connection');
        $cluster = $connections->get($connectionId);
        $scope = $cluster['data'] ?? [];
        $params = ['id' => $id, '_fragment' => DashboardListContext::RUNTIME_VERIFICATION_SECTION]
            + DashboardListContext::remediation($request);
        $problem = match (true) {
            'iac-image' !== $change->strategy => ['error' => 'This remediation does not support a Kubernetes rollout check.'],
            'deployed' === $change->getStatus() => ['error' => 'The running digest has already been verified. Refresh to view the recorded evidence.'],
            'approved' !== $change->getStatus() => ['error' => 'Approve the infrastructure update before checking the rollout.'],
            empty($change->data['image_verification']['image']) => ['error' => 'A verified upstream image digest is required to check the rollout.'],
            ($cluster['kind'] ?? null) !== 'cluster', ($scope['target'] ?? null) !== ($plan['context'] ?? null),
            empty($scope['credential']), !Connections::coversNamespace($scope, $plan['namespace'] ?? '') => [
                'error' => 'Choose a managed Kubernetes connection for the traced deployment.', 'field' => 'connection',
            ],
            default => null,
        };
        if (null !== $problem) {
            if ($json) {
                return new JsonResponse($problem, Response::HTTP_UNPROCESSABLE_ENTITY);
            }
            $this->addFlash('error', $problem['error']);

            return $this->redirectToRoute('change', $params, Response::HTTP_SEE_OTHER);
        }

        $note = null;
        $connectionName = $cluster['name'] ?? null;
        try {
            $credentials->kubernetes($scope['credential'], $plan['context'],
                fn (string $config): bool => $gitOps->observeIac($change, $config, $connectionId, $connectionName));
        } catch (\Symfony\Component\Yaml\Exception\ParseException | \JsonException) {
            $note = 'Could not read the managed kubeconfig. Check the credential bundle for this connection.';
        } catch (\DomainException $error) {
            $note = $error->getMessage();
        }
        if (null !== $note) {
            $this->store->record($id, 'rollout_unavailable', [
                'connection' => $connectionId, 'connection_name' => $connectionName, 'note' => $note,
            ]);
        }

        $redirect = $this->generateUrl('change', $params);

        return $json ? new JsonResponse(['redirect' => $redirect]) : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    #[Route('/api/remediations/{id}/pull-request-token', name: 'api_pull_request_token', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function pullRequestToken(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        $change = $this->changes->get($id);
        if (!$change || 'standalone-binary' === $change->strategy) {
            throw $this->createNotFoundException();
        }
        $purpose = 'pull-request-'.$id;

        return new JsonResponse([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/pull-request', name: 'change_pull_request', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function pullRequest(string $id, Request $request, DashboardPullRequests $pullRequests): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'pull-request-'.$id, $json)) {
            return $failure;
        }
        $headers = ['Cache-Control' => 'private, no-store'];
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        $operation = $request->request->getString('operation');
        $connection = $request->request->getString('connection');
        $base = $request->request->getString('base');
        $problem = null;
        try {
            if ('reprepare' === $operation) {
                $next = $pullRequests->reprepare($change, $connection, $base, $this->changes);
                $this->addFlash('success', 'Patch preparation selected for the current base revision.');

                $redirect = $this->returnToChange($next, $request, 'execution-timeline');

                return $json ? new JsonResponse(['redirect' => $redirect->headers->get('Location')], headers: $headers) : $redirect;
            }
            $note = match ($operation) {
                'publish' => 'Published verified pull request: '.$pullRequests->publish($change, $connection, $base),
                'merge' => $pullRequests->merge($change, $connection),
                'check_merge' => $pullRequests->merge($change, $connection, checkOnly: true),
                default => throw new \DomainException('Choose a pull request action.'),
            };
            $this->addFlash('success', $note);
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $problem = ['error' => 'Repository publication failed. Check the configured credential and branch restrictions.'];
        } catch (\UnexpectedValueException | \JsonException) {
            $problem = ['error' => 'The repository provider returned an unexpected response. Check the pull request before retrying.'];
        } catch (\DomainException $error) {
            $problem = ['error' => $error->getMessage(), 'field' => $error instanceof RemediationFieldError ? $error->field : null];
        }
        if (null !== $problem) {
            if ($json) {
                return new JsonResponse($problem, Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $problem['error']);
        }

        $draft = [];
        if (in_array($operation, ['publish', 'reprepare'], true) && strlen($base) <= 101 && !preg_match('/[\x00-\x1f\x7f]/', $base)) {
            $draft['publish_base'] = $base;
        }
        if (preg_match('/^[a-f0-9]{32}$/D', $connection)) {
            if (in_array($operation, ['publish', 'reprepare'], true)) {
                $draft['publish_connection'] = $connection;
            } elseif (in_array($operation, ['merge', 'check_merge'], true)) {
                $draft['merge_connection'] = $connection;
            }
        }
        $redirect = $this->generateUrl('change', ['id' => $id, '_fragment' => DashboardListContext::PULL_REQUEST_SECTION]
            + DashboardListContext::remediation($request) + $draft);

        return $json ? new JsonResponse(['redirect' => $redirect], headers: $headers) : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    #[Route('/api/remediations/{id}/tracking-token', name: 'api_release_tracking_token', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function releaseTrackingToken(string $id, ReleaseTracking $tracking, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        $change = $this->store->row('SELECT id, strategy, data FROM changes WHERE id = ?', [$id]);
        if (!$change || (!$tracking->get($id) && !$tracking->publication($change))) {
            throw $this->createNotFoundException();
        }
        $purpose = 'release-tracking-'.$id;

        return new JsonResponse([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/tracking', name: 'release_tracking', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function releaseTracking(string $id, Request $request, ReleaseTracking $tracking): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'release-tracking-'.$id, $json)) {
            return $failure;
        }
        try {
            $action = $request->request->getString('operation');
            $inline = $json && '1' === $request->request->getString('_inline');
            if ('save' === $action) {
                $version = $request->request->getString('_settings_version');
                $note = $tracking->save($id, $request->request->all(), '' === $version ? null : $version)
                    ? 'Tracking settings saved.' : 'Tracking settings unchanged.';
            } elseif (in_array($action, ['check', 'pause'], true)) {
                $tracking->schedule($id, 'check' === $action);
                $note = 'check' === $action ? 'Release check requested.' : 'Release tracking paused.';
            } else {
                throw new \DomainException('Choose a release tracking action.');
            }
            if ($inline) {
                return new JsonResponse(['message' => $note]);
            }
            $this->addFlash('release_tracking_success_'.$id, $note);
        } catch (\DomainException $error) {
            if ($json) {
                $failure = ['error' => $error->getMessage()];
                if ($error instanceof RemediationFieldError) {
                    $failure['field'] = $error->field;
                } elseif ($error instanceof ReleaseTrackingSettingsConflict) {
                    $failure['code'] = ReleaseTrackingSettingsConflict::CODE;
                }

                return new JsonResponse($failure, Response::HTTP_UNPROCESSABLE_ENTITY);
            }
            $this->addFlash('release_tracking_error_'.$id, $error->getMessage());
        }

        $redirect = $this->returnToChange($id, $request, 'release-tracking');

        return $json ? new JsonResponse(['redirect' => $redirect->headers->get('Location')]) : $redirect;
    }

    #[Route('/api/remediations/{id}/approval-tokens', name: 'api_approval_tokens', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function approvalTokens(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        if (false === $this->store->db->fetchOne('SELECT 1 FROM changes WHERE id = ?', [$id])) {
            throw $this->createNotFoundException();
        }

        return new JsonResponse([
            'approve-'.$id => $tokens->getToken('approve-'.$id)->getValue(),
            'independent-verification-'.$id => $tokens->getToken('independent-verification-'.$id)->getValue(),
        ], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/approve', name: 'approve', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function approve(string $id, Request $request): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'approve-'.$id, $json)) {
            return $failure;
        }
        $headers = ['Cache-Control' => 'private, no-store'];
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        $binary = 'standalone-binary' === $change->strategy;
        $section = DashboardListContext::APPROVAL_SECTION;
        try {
            $this->changes->approve($change);
            $this->addFlash('success', $binary ? 'Verified executable approved.' : 'Verified patch approved.');
            $section = $binary ? DashboardListContext::BINARY_INSTALLATION_SECTION : 'execution-timeline';
        } catch (\DomainException $error) {
            if ($json) {
                return new JsonResponse(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        }

        $redirect = $this->returnToChange($id, $request, $section);

        return $json ? new JsonResponse(['redirect' => $redirect->headers->get('Location')], headers: $headers) : $redirect;
    }

    #[Route('/remediations/{id}/independent-verification', name: 'change_independent_verification', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function independentlyVerify(string $id, Request $request, IndependentVerification $verification): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'independent-verification-'.$id, $json)) {
            return $failure;
        }
        $headers = ['Cache-Control' => 'private, no-store'];
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $verification->queue($change);
        } catch (\DomainException $error) {
            if ($json) {
                return new JsonResponse(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        }

        $redirect = $this->returnToChange($id, $request, DashboardListContext::APPROVAL_SECTION);

        return $json ? new JsonResponse(['redirect' => $redirect->headers->get('Location')], headers: $headers) : $redirect;
    }

    private function actionTokenFailure(Request $request, string $purpose, bool $json): ?JsonResponse
    {
        if ($this->isCsrfTokenValid($purpose, $request->request->getString('_token'))) {
            return null;
        }
        if ($json) {
            return new JsonResponse(['error' => 'Your remediation form expired. Try again.', 'code' => 'csrf_expired'],
                Response::HTTP_FORBIDDEN, ['Cache-Control' => 'private, no-store']);
        }
        throw $this->createAccessDeniedException('Invalid form token.');
    }

    #[Route('/api/remediations/{id}/retry-preparation-token', name: 'api_retry_preparation_token', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function retryPreparationToken(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        $change = $this->changes->get($id);
        if (!$change || !Changes::canRetryPreparation($change)) {
            throw $this->createNotFoundException();
        }
        $purpose = 'retry-preparation-'.$id;

        return new JsonResponse([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/retry-preparation', name: 'change_retry_preparation', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function retryPreparation(string $id, Request $request, BinaryTargets $binaries): Response
    {
        $json = 'json' === $request->getPreferredFormat();
        if ($failure = $this->actionTokenFailure($request, 'retry-preparation-'.$id, $json)) {
            return $failure;
        }
        $headers = ['Cache-Control' => 'private, no-store'];
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            if ('standalone-binary' === $change->strategy && Changes::canRetryPreparation($change) && !$this->changes->nextAttempt($id)) {
                $binaries->checkRetryTarget($change);
            }

            $redirect = $this->returnToChange($this->changes->retryPreparation($change), $request, 'execution-timeline');

            return $json ? new JsonResponse(['redirect' => $redirect->headers->get('Location')], headers: $headers) : $redirect;
        } catch (\DomainException | \InvalidArgumentException $error) {
            $message = $error->getMessage();
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $message = 'Could not check the registered executable. Confirm the source and host connection before retrying.';
        }
        if ($json) {
            return new JsonResponse(['error' => $message], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        }
        $this->addFlash('error', $message);

        return $this->redirectToRoute('change', [
            'id' => $id, 'events' => 'failed', '_fragment' => 'execution-timeline',
        ] + DashboardListContext::remediation($request), Response::HTTP_SEE_OTHER);
    }

    private function returnToChange(string $id, Request $request, string $fragment = ''): Response
    {
        $context = DashboardListContext::withPreparationJobAttempt(DashboardListContext::remediation($request), $id);

        return $this->redirectToRoute('change', ['id' => $id, '_fragment' => $fragment] + $context, Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/patch', name: 'patch', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function patch(string $id): Response
    {
        $patch = $this->changes->get($id)?->data['patch'] ?? throw $this->createNotFoundException();

        return new Response($patch, headers: [
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Content-Disposition' => 'attachment; filename="patchrocket-'.$id.'.diff"',
        ]);
    }

    private function requireToken(Request $request, string $purpose): void
    {
        if (!$this->isCsrfTokenValid($purpose, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
    }

    /** @return array{rows: array, total: int|null, selectedPage: int|null} */
    private function findings(int $limit, int $offset = 0, array $filters = [], bool $countMatches = false, ?string $selectedId = null): array
    {
        $filters += [
            'observation' => 'detected', 'asset' => '', 'severity' => '', 'fix' => false, 'advisory' => '', 'view' => 'findings',
            'assetName' => '', 'package' => '', 'ecosystem' => '', 'runtime' => '', 'exactAsset' => false, 'findingId' => '', 'scanTarget' => '',
        ];
        ['observation' => $observation, 'asset' => $asset, 'severity' => $severity, 'fix' => $fix, 'advisory' => $advisory, 'view' => $view,
            'assetName' => $assetName, 'package' => $package, 'ecosystem' => $ecosystem, 'runtime' => $runtime, 'exactAsset' => $exactAsset,
            'findingId' => $findingId, 'scanTarget' => $scanTarget] = $filters;
        $detected = match ($observation) {
            'absent' => false,
            'all' => null,
            default => true,
        };
        $severityField = $this->findingField('severity');
        $fixField = $this->findingField('fixed');
        $where = [];
        $params = [];
        $scope = $asset && !$exactAsset ? Inventory::scopeSql().' ' : '';
        $scopeParams = '' !== $scope ? [$asset] : [];
        if ($asset) {
            $where[] = $exactAsset ? 'f.asset_id = ?' : 'f.asset_id IN (SELECT id FROM scope)';
            if ($exactAsset) {
                $params[] = $asset;
            }
        }
        if (null !== $detected) {
            $where[] = 'f.active = ?';
            $params[] = (int) $detected;
        }
        if ('' !== $findingId) {
            $where[] = 'f.id = ?';
            $params[] = $findingId;
        }
        foreach (['a.name' => $assetName, $this->store->jsonText('f.data', 'target') => $scanTarget] as $field => $search) {
            if ('' !== $search) {
                $where[] = "LOWER($field) LIKE LOWER(?) ESCAPE '!'";
                $params[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            }
        }
        $advisoryField = $this->findingField('advisory');
        if ($advisory) {
            $where[] = "UPPER($advisoryField) = ?";
            $params[] = $advisory;
        }
        if ('' !== $package) {
            $where[] = 'LOWER('.$this->findingField('package').') = LOWER(?)';
            $params[] = $package;
        }
        if ('' !== $ecosystem) {
            $where[] = 'LOWER('.$this->findingField('type').') = LOWER(?)';
            $params[] = $ecosystem;
        }
        if ($severity) {
            $where[] = "$severityField = ?";
            $params[] = strtoupper($severity);
        }
        if ($fix) {
            $where[] = "$fixField <> ''";
        }
        if ('' !== $runtime) {
            $where[] = 'f.asset_id IN ('.$this->inventory->runtimeFindingAssetIds('running' === $runtime).')';
        }

        $from = ' FROM findings f JOIN assets a ON a.id = f.asset_id'.($where ? ' WHERE '.implode(' AND ', $where) : '');
        $rank = "CASE $severityField WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
        $fixRank = "CASE WHEN $fixField <> '' THEN 1 ELSE 0 END";
        $groupBy = '';
        if ('advisories' === $view) {
            $columns = "$advisoryField AS advisory, MIN($rank) AS severity_rank, COUNT(DISTINCT f.asset_id) AS asset_count,
                COUNT(*) AS finding_count, SUM(f.active) AS detected_count, SUM($fixRank) AS fix_count, MAX(f.active) AS active";
            $groupBy = " GROUP BY $advisoryField";
            $orderBy = 'active DESC, severity_rank, asset_count DESC, advisory';
        } elseif ('assets' === $view) {
            $columns = "a.id AS asset_id, a.name AS asset_name, a.kind AS asset_kind, MIN($rank) AS severity_rank,
                COUNT(*) AS finding_count, SUM(f.active) AS detected_count, SUM($fixRank) AS fix_count, MAX(f.active) AS active,
                CASE WHEN EXISTS(SELECT 1 FROM asset_links l WHERE l.source_id = a.id AND l.kind = 'BUILD_SOURCE') THEN 1 ELSE 0 END AS has_build_source";
            $groupBy = ' GROUP BY a.id, a.name, a.kind';
            $orderBy = 'active DESC, severity_rank, asset_name, asset_id';
        } else {
            $columns = 'f.*, a.name AS asset_name';
            $orderBy = "f.active DESC, $rank, $fixRank DESC, f.last_seen DESC, f.id";
        }
        if (null !== $selectedId && '' === $groupBy) {
            $position = $this->store->db->fetchOne(
                "$scope SELECT result_position FROM (SELECT f.id, ROW_NUMBER() OVER (ORDER BY $orderBy) AS result_position$from) ranked_findings WHERE id = ?",
                [...$scopeParams, ...$params, $selectedId],
            );

            return ['rows' => [], 'total' => null, 'selectedPage' => false === $position ? null : intdiv((int) $position - 1, $limit) + 1];
        }
        if (null !== $selectedId) {
            // Compare the IDs used in shared links in the same order as the paged results.
            $key = 'advisories' === $view ? 'advisory' : 'asset_id';
            $position = 0;
            $selectedPage = null;
            foreach ($this->store->db->iterateColumn(
                "$scope SELECT $key FROM (SELECT $columns$from$groupBy) finding_groups ORDER BY $orderBy",
                [...$scopeParams, ...$params],
            ) as $value) {
                $id = 'advisory' === $key ? hash('sha256', (string) $value) : $value;
                if ($id === $selectedId) {
                    $selectedPage = intdiv($position, $limit) + 1;
                    break;
                }
                ++$position;
            }

            return ['rows' => [], 'total' => null, 'selectedPage' => $selectedPage];
        }
        $countQuery = '' === $groupBy ? 'SELECT COUNT(*)'.$from : 'SELECT COUNT(*) FROM (SELECT 1'.$from.$groupBy.') matching_groups';
        $countColumn = $countMatches ? ", ($countQuery) AS match_count" : '';
        $rows = $this->store->rows(
            "$scope SELECT $columns$countColumn$from$groupBy ORDER BY $orderBy LIMIT $limit OFFSET $offset",
            [...$scopeParams, ...($countMatches ? $params : []), ...$params],
        );
        $total = null;
        if ($countMatches) {
            // An out-of-range page has no row to carry the count.
            $total = isset($rows[0]) ? (int) $rows[0]['match_count'] : (0 === $offset ? 0
                : (int) $this->store->db->fetchOne($scope.$countQuery, [...$scopeParams, ...$params]));
            foreach (array_keys($rows) as $index) {
                unset($rows[$index]['match_count']);
            }
        }

        return ['rows' => $rows, 'total' => $total, 'selectedPage' => null];
    }

    private function findingTableRows(array $findings): array
    {
        return array_map(static fn (array $finding): array => self::detailFields($finding, ['id', 'asset_id', 'asset_name', 'source', 'active', 'last_seen'])
            + ['details' => self::detailFields($finding['data'], self::FINDING_SUMMARY_FIELDS)], $findings);
    }

    private function findingField(string $name): string
    {
        return $this->store->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
            ? "json_extract(f.data, '$.$name')"
            : "(CAST(f.data AS jsonb)->>'$name')";
    }
}
