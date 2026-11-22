<?php
declare(strict_types=1);

namespace App\Controller;

use App\Auth\DashboardReturnPath;
use Symfony\Component\HttpFoundation\Request;

final class DashboardListContext
{
    public const OVERVIEW = '/';
    public const ASSETS = ['/assets', '/app/assets', '/app'];
    public const FINDINGS = ['/findings'];
    public const FINDING_RESULT_PREFIX = 'finding-result-';
    public const ASSET_FINDING_PREFIX = 'asset-finding-';
    public const ASSET_RELATION_PREFIX = 'asset-relation-';
    public const ASSET_RELATIONS_SECTION = 'related-assets';
    public const ASSET_VULNERABILITIES_SECTION = 'asset-vulnerabilities';
    public const ASSET_SCAN_SCHEDULE_SECTION = 'asset-scan-schedule';
    public const RECURRING_SCANS_SECTION = 'recurring-scans';
    public const SAVED_SCAN_SCHEDULES_SECTION = 'saved-scan-schedules';
    public const SAVED_SCAN_SCHEDULE_PREFIX = 'saved-scan-schedule-';
    public const REMEDIATION_HISTORY_SECTION = 'remediation-history';
    public const REMEDIATION_ORIGINAL_FINDING_LINK = 'remediation-original-finding';
    public const REMEDIATIONS = ['/remediations', '/app/remediations'];
    public const FLEET = ['/fleet', '/app/fleet'];
    public const EXECUTABLES = '/binaries';
    public const EXECUTABLE_RESULTS = 'executable-results';
    public const EXECUTABLE_RESULT_PREFIX = 'executable-result-';
    public const EXECUTABLE_REGISTRATION = 'executable-registration';
    public const BINARY_INSTALLATION_SECTION = 'binary-installation';
    public const QUEUE = '/app/queue';
    public const RELEASE_TRACKERS_SECTION = 'release-trackers';
    public const REMEDIATION_JOBS_SECTION = 'remediation-jobs';
    public const APPROVAL_SECTION = 'approval';
    public const APPROVAL_POLICY_EDITOR_SECTION = 'approval-policy-editor';
    private const ROLLOUT_SCHEDULE_PREFIX = 'rollout-schedule-';
    public const RELEASE_TRACKING_SECTION = 'release-tracking';
    public const PULL_REQUEST_SECTION = 'pull-request';
    public const RUNTIME_VERIFICATION_SECTION = 'runtime-verification';
    public const PACKAGE_UPDATES_SECTION = 'package-updates';
    public const VM_PACKAGE_JOBS_SECTION = 'vm-package-jobs';
    public const FINDING_DETAILS_SECTION = 'finding-details';
    public const FINDING_RUNTIME_LINK = 'finding-runtime';
    public const FINDING_ADVISORY_LINK = 'finding-advisory';
    public const FINDING_BUILD_SOURCE_SECTION = 'build-source';
    public const FINDING_DEPLOYMENT_SOURCE_SECTION = 'deployment-source';
    public const FINDING_RELATED_SOURCE_SECTION = 'related-source';
    public const GETTING_STARTED = '/settings/getting-started';
    public const GETTING_STARTED_CONNECTIONS_SECTION = 'getting-started-inventory';
    public const DISCOVERY_SECTION = 'getting-started-discovery';
    public const GETTING_STARTED_POLICY_SECTION = 'getting-started-policy';
    private const GETTING_STARTED_WORKER_CHECKS = ['getting-started-inventory-worker', 'getting-started-checks-worker'];
    public const CONNECTIONS_SECTION = 'infrastructure-connections';
    public const ARGO_SECTION = 'argocd';
    public const DELIVERY_SOURCE_PREFIX = 'delivery-source-';
    public const DELIVERY_CANDIDATE_PREFIX = 'delivery-candidate-';
    private const CONNECTION_RESULT = '~^connection-result-(?:[a-f0-9]{32}|[a-f0-9]{64})$~D';
    private const ASSET_DETAIL_SECTIONS = [null, 'scan-failure', 'asset-title', self::ASSET_SCAN_SCHEDULE_SECTION];

    public static function asset(Request $request): array
    {
        $from = $request->query->all()['from'] ?? null;
        $connectionContext = self::connectionSettings($from);
        if (null !== self::overview($from) || null !== self::findingDetailId($from) || null !== self::findingSource($from)
            || null !== self::vmPackageQueue($from) || null !== self::relatedAsset($from) || null !== self::executables($from)) {
            return ['from' => $from];
        }

        return in_array($connectionContext['kind'] ?? null, ['queue', 'getting-started'], true)
            ? ['from' => $connectionContext['url']] : self::parameters($request, [...self::ASSETS, ...self::FINDINGS, ...self::FLEET]);
    }

    public static function executables(mixed $value): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || self::EXECUTABLES !== parse_url($url, PHP_URL_PATH)) {
            return null;
        }
        $fragment = parse_url($url, PHP_URL_FRAGMENT);

        return self::EXECUTABLE_RESULTS === $fragment
            || (null !== $fragment && preg_match('~^'.self::EXECUTABLE_RESULT_PREFIX.'[a-f0-9]{64}$~D', $fragment))
            ? $url : null;
    }

    public static function assetDetail(mixed $value, array $sections = self::ASSET_DETAIL_SECTIONS): ?string
    {
        $from = DashboardReturnPath::validate($value);
        if (null !== $from && preg_match('~^/assets/[a-f0-9]{64}$~D', parse_url($from, PHP_URL_PATH))
            && in_array(parse_url($from, PHP_URL_FRAGMENT), $sections, true)) {
            return $from;
        }

        return null;
    }

    /** @return array{url: string, label: string}|null */
    public static function scopedInventoryReturn(mixed $value, bool $canManageSettings): ?array
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || !in_array(parse_url($url, PHP_URL_PATH), self::ASSETS, true)
            || !preg_match('/^asset-result-[a-f0-9]{64}$/D', parse_url($url, PHP_URL_FRAGMENT) ?? '')) {
            return null;
        }

        $query = Request::create($url)->query->all();
        $label = null;
        foreach ([
            'failed_connection' => ['/^[a-f0-9]{32}$/D', 'Failed scan images'],
            'running_image' => ['/^[a-f0-9]{64}$/iD', 'Running containers'],
            'scope' => ['/^[a-f0-9]{64}$/iD', 'Scoped assets'],
        ] as $parameter => [$pattern, $scopeLabel]) {
            $id = $query[$parameter] ?? '';
            if ('' === $id) {
                continue;
            }
            if (!is_string($id) || !preg_match($pattern, $id) || ('failed_connection' === $parameter && !$canManageSettings)) {
                return null;
            }
            $label ??= $scopeLabel;
        }

        return null === $label ? null : ['url' => $url, 'label' => $label];
    }

    public static function scanSettingsAssetReturn(mixed $value): ?string
    {
        return self::assetDetail($value, [...self::ASSET_DETAIL_SECTIONS, self::ASSET_VULNERABILITIES_SECTION]);
    }

    /** @return array{url: string, id: string}|null */
    public static function scanSettingsSelection(mixed $value): ?array
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || '/settings/scanning' !== parse_url($url, PHP_URL_PATH)
            || self::RECURRING_SCANS_SECTION !== parse_url($url, PHP_URL_FRAGMENT)) {
            return null;
        }
        $asset = Request::create($url)->query->all()['asset'] ?? null;

        return is_string($asset) && preg_match('/^[a-f0-9]{64}$/D', $asset) ? ['url' => $url, 'id' => $asset] : null;
    }

    public static function assetFinding(mixed $value): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null !== $url && preg_match('~^/assets/[a-f0-9]{64}$~D', parse_url($url, PHP_URL_PATH))
            && preg_match('~^'.self::ASSET_FINDING_PREFIX.'[a-f0-9]{64}$~D', parse_url($url, PHP_URL_FRAGMENT) ?? '')) {
            return $url;
        }

        return null;
    }

    public static function discoveryChecklist(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && self::GETTING_STARTED === parse_url($from, PHP_URL_PATH)
            && self::DISCOVERY_SECTION === parse_url($from, PHP_URL_FRAGMENT) ? $from : null;
    }

    /** @return array{url: string, label: string}|null */
    public static function workerQueueReturn(mixed $value, bool $canManageSettings = false): ?array
    {
        $from = DashboardReturnPath::validate($value);
        if (null === $from) {
            return null;
        }
        $path = parse_url($from, PHP_URL_PATH);
        $fragment = parse_url($from, PHP_URL_FRAGMENT) ?? '';
        if ($canManageSettings && self::GETTING_STARTED === $path && in_array($fragment, self::GETTING_STARTED_WORKER_CHECKS, true)) {
            return ['url' => $from, 'label' => 'Return to installation checks'];
        }
        if (self::QUEUE !== $path) {
            return null;
        }
        $standard = DashboardReturnPath::queueSection($from);
        $label = match (true) {
            null !== $standard && str_starts_with($fragment, 'inventory-jobs/') => 'Return to inventory job',
            null !== $standard && str_starts_with($fragment, 'scheduled-scans/') => 'Return to scheduled scan',
            1 === preg_match('~^remediation-jobs/(?:prepare|independent)/[a-f0-9]{24}$~D', $fragment) => 'Return to remediation job',
            1 === preg_match('~^connection-checks/[a-f0-9]{32}$~D', $fragment) => 'Return to connection check',
            1 === preg_match('~^vm-package-jobs/[a-f0-9]{64}$~D', $fragment) => 'Return to VM package update',
            1 === preg_match('~^transports/[a-z][a-z0-9_-]{0,63}$~D', $fragment) => 'Return to queue',
            default => null,
        };

        return null === $label ? null : ['url' => $from, 'label' => $label];
    }

    /** @return array{url: string, transport: string}|null */
    public static function workerSetupQueue(mixed $value): ?array
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || self::QUEUE !== parse_url($url, PHP_URL_PATH) || 'workers' !== parse_url($url, PHP_URL_FRAGMENT)) {
            return null;
        }
        $transport = Request::create($url)->query->all()['worker_transport'] ?? null;

        return in_array($transport, ['jobs', 'kubernetes_checks'], true) ? ['url' => $url, 'transport' => $transport] : null;
    }

    /** @return array{url: string, label: string}|null */
    public static function policySettings(mixed $value): ?array
    {
        if ($asset = self::assetDetail($value, ['asset-title'])) {
            return ['url' => $asset, 'label' => 'Return to repository'];
        }
        if ($url = self::remediationDetail($value, self::APPROVAL_SECTION)) {
            return ['url' => $url, 'label' => 'Return to approval'];
        }
        if ($url = self::remediationDetail($value, 'execution-timeline')) {
            return ['url' => $url, 'label' => 'Return to remediation'];
        }
        $url = DashboardReturnPath::validate($value);
        if (null !== $url && self::GETTING_STARTED === parse_url($url, PHP_URL_PATH)
            && self::GETTING_STARTED_POLICY_SECTION === parse_url($url, PHP_URL_FRAGMENT)) {
            return ['url' => $url, 'label' => 'Return to Getting started'];
        }

        return null;
    }

    public static function remediationDetail(mixed $value, string $section): ?string
    {
        $url = DashboardReturnPath::validate($value);

        return null !== $url && $section === parse_url($url, PHP_URL_FRAGMENT)
            && preg_match('~^/remediations/[a-f0-9]{24}$~D', parse_url($url, PHP_URL_PATH)) ? $url : null;
    }

    public static function relatedAsset(mixed $value): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null !== $url && preg_match('~^/assets/[a-f0-9]{64}$~D', parse_url($url, PHP_URL_PATH))
            && preg_match('~^'.self::ASSET_RELATION_PREFIX.'[a-f0-9]{64}$~D', parse_url($url, PHP_URL_FRAGMENT) ?? '')) {
            return $url;
        }

        return null;
    }

    public static function finding(Request $request): array
    {
        $from = $request->query->all()['from'] ?? null;
        $source = self::findingSource($from);
        $return = self::assetFinding($from) ?? self::overview($from)
            ?? self::remediationDetail($from, self::REMEDIATION_ORIGINAL_FINDING_LINK)
            ?? (self::FINDING_RELATED_SOURCE_SECTION === ($source['section'] ?? null) ? $from : null);

        return null !== $return ? ['from' => $return] : self::parameters($request, self::FINDINGS);
    }

    private static function overview(mixed $value, bool $remediation = false): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || self::OVERVIEW !== parse_url($url, PHP_URL_PATH)) {
            return null;
        }

        $pattern = $remediation ? '/^remediation-result-[a-f0-9]{24}$/D' : '/^'.self::FINDING_RESULT_PREFIX.'[a-f0-9]{64}$/D';

        return preg_match($pattern, parse_url($url, PHP_URL_FRAGMENT) ?? '') ? $url : null;
    }

    public static function overviewScan(mixed $value): ?string
    {
        $url = DashboardReturnPath::validate($value);

        return null !== $url && self::OVERVIEW === parse_url($url, PHP_URL_PATH)
            && preg_match('/^overview-scan-(?:recorded|failed|unscanned|assets-due|connections-due)$/D', parse_url($url, PHP_URL_FRAGMENT) ?? '')
            ? $url : null;
    }

    /** @return array{url: string, view: string, label: string}|null */
    public static function findingGroup(Request $request): ?array
    {
        $url = self::parameters($request, self::FINDINGS, 'group_from')['group_from'] ?? null;
        if (null === $url) {
            return null;
        }

        parse_str(parse_url($url, PHP_URL_QUERY) ?? '', $query);
        $fragment = parse_url($url, PHP_URL_FRAGMENT) ?? '';
        return match (true) {
            'advisories' === ($query['view'] ?? null) && 1 === preg_match('/^advisory-result-[a-f0-9]{64}$/D', $fragment)
                => ['url' => $url, 'view' => 'advisories', 'label' => 'Advisory groups'],
            'assets' === ($query['view'] ?? null) && 1 === preg_match('/^affected-asset-result-[a-f0-9]{64}$/D', $fragment)
                => ['url' => $url, 'view' => 'assets', 'label' => 'Affected assets'],
            default => null,
        };
    }

    /** @return array{url: string, kind: string, label: string}|null */
    public static function connectionSettings(mixed $value): ?array
    {
        if ($queue = DashboardReturnPath::queueSection($value)) {
            return ['url' => $queue, 'kind' => 'queue', 'label' => 'Queue'];
        }
        if ($list = self::connectionList($value)) {
            return ['url' => $list, 'kind' => self::CONNECTIONS_SECTION, 'label' => 'Infrastructure connections'];
        }
        if ($source = self::deliverySource($value) ?? self::deliveryCandidate($value)) {
            return ['url' => $source, 'kind' => 'delivery-discovery', 'label' => 'Service discovery'];
        }
        $from = DashboardReturnPath::validate($value);
        if (null !== $from && self::GETTING_STARTED === parse_url($from, PHP_URL_PATH)) {
            $section = parse_url($from, PHP_URL_FRAGMENT) ?? '';
            if (in_array($section, [self::DISCOVERY_SECTION, 'getting-started-manage-sources', 'getting-started-manage-targets'], true)
                || preg_match('~^getting-started-connect-(?:source|vm|docker|registry|cluster)$~D', $section)) {
                return ['url' => $from, 'kind' => 'getting-started', 'label' => 'Getting started'];
            }
        }
        if (null !== $from && self::PACKAGE_UPDATES_SECTION === parse_url($from, PHP_URL_FRAGMENT)
            && preg_match('~^/assets/[a-f0-9]{64}$~D', parse_url($from, PHP_URL_PATH))) {
            return ['url' => $from, 'kind' => self::PACKAGE_UPDATES_SECTION, 'label' => 'Package updates'];
        }
        if (null !== $from && preg_match('~^/remediations/[a-f0-9]{24}$~D', parse_url($from, PHP_URL_PATH))) {
            $section = parse_url($from, PHP_URL_FRAGMENT);
            if (is_string($section) && preg_match('~^execution-event-[0-9]{20}-[a-f0-9]{12}$~D', $section)) {
                return ['url' => $from, 'kind' => self::RUNTIME_VERIFICATION_SECTION, 'label' => 'Rollout evidence'];
            }
            $label = match ($section) {
                self::PULL_REQUEST_SECTION => 'Pull request',
                self::RUNTIME_VERIFICATION_SECTION => 'Runtime verification',
                self::RELEASE_TRACKING_SECTION => 'Release tracking',
                default => null,
            };
            if (null !== $label) {
                return ['url' => $from, 'kind' => $section, 'label' => $label];
            }
        }

        return null;
    }

    public static function connectionList(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && '/settings/connections' === parse_url($from, PHP_URL_PATH)
            && self::CONNECTIONS_SECTION === parse_url($from, PHP_URL_FRAGMENT) ? $from : null;
    }

    public static function kubernetesDirectory(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);
        $fragment = null === $from ? null : parse_url($from, PHP_URL_FRAGMENT);

        return null !== $from && '/app/clusters' === parse_url($from, PHP_URL_PATH)
            && (null === $fragment || 'cluster-connections' === $fragment || preg_match(self::CONNECTION_RESULT, $fragment)) ? $from : null;
    }

    /** @return array{url: string, label: string}|null */
    public static function inventoryDirectory(mixed $value): ?array
    {
        $from = DashboardReturnPath::validate($value);
        if (null === $from || !preg_match(self::CONNECTION_RESULT, parse_url($from, PHP_URL_FRAGMENT) ?? '')) {
            return null;
        }

        return match (parse_url($from, PHP_URL_PATH)) {
            '/app/clusters' => ['url' => $from, 'label' => 'Kubernetes connections'],
            '/app/repositories' => ['url' => $from, 'label' => 'Source repositories'],
            default => null,
        };
    }

    public static function deliverySource(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && '/settings/discovery' === parse_url($from, PHP_URL_PATH)
            && preg_match('~^'.self::DELIVERY_SOURCE_PREFIX.'(?:[a-f0-9]{32}|[a-f0-9]{64})$~D', parse_url($from, PHP_URL_FRAGMENT) ?? '') ? $from : null;
    }

    public static function deliveryCandidate(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && '/settings/discovery' === parse_url($from, PHP_URL_PATH)
            && preg_match('~^'.self::DELIVERY_CANDIDATE_PREFIX.'[a-f0-9]{64}$~D', parse_url($from, PHP_URL_FRAGMENT) ?? '') ? $from : null;
    }

    public static function argoSettings(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && '/settings/integrations' === parse_url($from, PHP_URL_PATH)
            && self::ARGO_SECTION === parse_url($from, PHP_URL_FRAGMENT) ? $from : null;
    }

    /** @return array{url: string, kind: string, label: string}|null */
    public static function credentialSettings(mixed $value): ?array
    {
        $context = self::connectionSettings($value);
        if ('getting-started' === ($context['kind'] ?? null)) {
            return $context;
        }
        $from = DashboardReturnPath::validate($value);
        if (null === $from) {
            return null;
        }
        $path = parse_url($from, PHP_URL_PATH);
        $section = parse_url($from, PHP_URL_FRAGMENT);
        if (self::argoSettings($from)) {
            $cluster = Request::create($from)->query->all()['argo_cluster'] ?? null;
            if (is_string($cluster) && preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $cluster)) {
                return ['url' => $from, 'kind' => 'connection-editor', 'label' => 'Argo CD settings'];
            }
        }
        $label = match (true) {
            '/app/repositories' === $path && null === $section => 'Repository connection',
            '/app/clusters' === $path && null === $section => 'Kubernetes connection',
            '/settings/connections' === $path && 'connection-vm' === $section => 'VM connection',
            '/settings/connections' === $path && 'ansible-inventory' === $section => 'Ansible inventory import',
            default => null,
        };
        if (null === $label) {
            return null;
        }
        $edit = Request::create($from)->query->all()['edit'] ?? null;
        if (('/settings/connections' === $path ? null === $edit : 'new' === $edit)
            || (is_string($edit) && preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $edit))) {
            return ['url' => $from, 'kind' => 'connection-editor', 'label' => $label];
        }

        return null;
    }

    public static function remediation(Request $request): array
    {
        $from = $request->query->all()['from'] ?? null;
        if (null !== self::overview($from, remediation: true) || null !== self::findingHistory($from) || null !== self::executables($from)
            || ('admin' === $request->attributes->get('_dashboard_role') && null !== self::rolloutSchedule($from))) {
            return ['from' => $from];
        }
        $parameters = self::parameters($request, [...self::REMEDIATIONS, self::QUEUE]);
        if (self::QUEUE === parse_url($parameters['from'] ?? '', PHP_URL_PATH)) {
            $fragment = parse_url($parameters['from'], PHP_URL_FRAGMENT) ?? '';
            if (!preg_match('~^'.self::REMEDIATION_JOBS_SECTION.'(?:/(?:prepare|independent)/[a-f0-9]{24})?$~D', $fragment)
                && !preg_match('~^'.self::RELEASE_TRACKERS_SECTION.'(?:/[a-f0-9]{24})?$~D', $fragment)) {
                $section = str_starts_with($fragment, self::REMEDIATION_JOBS_SECTION.'/')
                    ? self::REMEDIATION_JOBS_SECTION : self::RELEASE_TRACKERS_SECTION;
                $parameters['from'] = explode('#', $parameters['from'], 2)[0].'#'.$section;
            }
        }

        return $parameters;
    }

    public static function rolloutSchedule(mixed $value): ?string
    {
        $from = DashboardReturnPath::validate($value);

        return null !== $from && '/settings/policy' === parse_url($from, PHP_URL_PATH)
            && preg_match('~^'.self::ROLLOUT_SCHEDULE_PREFIX.'[a-f0-9]{24}$~D', parse_url($from, PHP_URL_FRAGMENT) ?? '') ? $from : null;
    }

    public static function withPreparationJobAttempt(array $context, string $id): array
    {
        $from = $context['from'] ?? '';
        $prefix = self::REMEDIATION_JOBS_SECTION.'/prepare/';
        if (self::QUEUE === parse_url($from, PHP_URL_PATH)
            && str_starts_with(parse_url($from, PHP_URL_FRAGMENT) ?? '', $prefix)) {
            $context['from'] = explode('#', $from, 2)[0].'#'.$prefix.$id;
        }

        return $context;
    }

    /** @return array{id: string, from?: string, history_q?: string, history_page?: int}|null */
    public static function findingHistory(mixed $value): ?array
    {
        $path = DashboardReturnPath::validate($value);
        if (null === $path || self::REMEDIATION_HISTORY_SECTION !== parse_url($path, PHP_URL_FRAGMENT)
            || !preg_match('~^/findings/([a-f0-9]{64})$~D', parse_url($path, PHP_URL_PATH), $match)) {
            return null;
        }

        $request = Request::create($path);

        return ['id' => $match[1]] + self::finding($request) + self::findingHistoryFilters($request);
    }

    /** @return array{history_q?: string, history_page?: int} */
    public static function findingHistoryFilters(Request $request): array
    {
        $query = $request->query->all();
        $search = is_string($query['history_q'] ?? null) ? trim($query['history_q']) : '';
        $page = filter_var($query['history_page'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: 1;

        return ('' === $search ? [] : ['history_q' => $search]) + ($page > 1 ? ['history_page' => min(100000, $page)] : []);
    }

    public static function findingDetailId(mixed $value, string $fragment = self::FINDING_DETAILS_SECTION): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null !== $url && $fragment === parse_url($url, PHP_URL_FRAGMENT)
            && preg_match('~^/findings/([a-f0-9]{64})$~D', parse_url($url, PHP_URL_PATH), $match)) {
            return $match[1];
        }

        return null;
    }

    /** @return array{section: string, label: string}|null */
    public static function findingSource(mixed $value): ?array
    {
        $url = DashboardReturnPath::validate($value);
        if (null === $url || !preg_match('~^/findings/[a-f0-9]{64}$~D', parse_url($url, PHP_URL_PATH))) {
            return null;
        }
        [$section, $target] = array_pad(explode('/', parse_url($url, PHP_URL_FRAGMENT) ?: '', 2), 2, null);
        if (null !== $target && !preg_match('/^[a-f0-9]{64}$/D', $target)) {
            return null;
        }
        $label = match ($section) {
            self::FINDING_BUILD_SOURCE_SECTION => 'Build source',
            self::FINDING_DEPLOYMENT_SOURCE_SECTION => 'Deployment source',
            self::FINDING_RELATED_SOURCE_SECTION => 'Related source',
            default => null,
        };

        return null === $label ? null : ['section' => $section, 'label' => $label];
    }

    public static function vmPackageQueue(mixed $value): ?string
    {
        $url = DashboardReturnPath::validate($value);
        if (null !== $url && self::QUEUE === parse_url($url, PHP_URL_PATH)
            && preg_match('~^'.self::VM_PACKAGE_JOBS_SECTION.'(?:/[a-f0-9]{64})?$~D', parse_url($url, PHP_URL_FRAGMENT) ?? '')) {
            return $url;
        }

        return null;
    }

    public static function parameters(Request $request, array $listPaths, string $parameter = 'from'): array
    {
        $from = DashboardReturnPath::validate($request->query->all()[$parameter] ?? null);
        if (null !== $from && in_array(parse_url($from, PHP_URL_PATH), $listPaths, true)) {
            return [$parameter => $from];
        }

        return [];
    }
}
