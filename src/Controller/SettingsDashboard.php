<?php
declare(strict_types=1);

namespace App\Controller;

use App\AI\Compatibility;
use App\AI\CodexFixture;
use App\AI\ModelDiscovery;
use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardReturnPath;
use App\Discovery\Repository;
use App\Fleet\RolloutSchedules;
use App\Intelligence\ScanSchedules;
use App\Intelligence\Scanner;
use App\Queue\SchedulerActivity;
use App\Queue\WorkerPresence;
use App\Remediation\ApprovalPolicy;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\AnsibleInventory;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use App\Verification\Sandbox;
use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\ParameterType;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\InputBag;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class SettingsDashboard extends AbstractController
{
    private const ROLLOUT_DRAFT = 'rollout-schedule-draft';
    private const ARGO_DRAFT = 'argo-settings-draft';
    private const REPOSITORY_PICKER_LIMIT = 20;

    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Connections $connections,
        private readonly OperatorSettings $operator,
        private readonly ScanSchedules $scans,
        private readonly ApprovalPolicy $approvals,
        private readonly RolloutSchedules $rollouts,
        private readonly SecretManagers $managers,
        private readonly JenkinsConnections $jenkins,
        private readonly PreactPage $preact,
        private readonly CsrfTokenManagerInterface $tokens,
    ) {
    }

    #[Route('/settings', name: 'settings', methods: ['GET'])]
    public function settings(Request $request): Response
    {
        $edit = $request->query->getString('edit');
        if ('' !== $edit) {
            return $this->redirectToRoute('settings_connections', ['edit' => $edit]);
        }

        return $this->preact->render('settings');
    }

    #[Route('/settings/getting-started', name: 'settings_getting-started', methods: ['GET'])]
    public function gettingStarted(Request $request, WorkerPresence $workers): Response
    {
        $selected = $request->query->getString('connection');
        $filters = self::discoveryFilters($request->query);
        $from = $request->query->all()['from'] ?? null;

        return $this->preact->render('settings-getting-started', $this->gettingStartedSnapshot($workers, $selected, $filters) + [
            'queueReturn' => DashboardReturnPath::queueSection($from, 'inventory-jobs'),
            'workerSetupReturn' => DashboardListContext::workerSetupQueue($from),
            'urls' => [
                'status' => $this->generateUrl('settings_getting_started_status', ('' !== $selected ? ['connection' => $selected] : []) + $filters),
                'queue' => $this->generateUrl('frontend_dashboard', ['view' => 'queue', '_fragment' => 'workers']),
                'inventory_workers' => $this->generateUrl('frontend_dashboard', [
                    'view' => 'queue', 'worker_transport' => 'jobs', '_fragment' => 'workers',
                ]),
                'connection_check_workers' => $this->generateUrl('frontend_dashboard', [
                    'view' => 'queue', 'worker_transport' => 'kubernetes_checks', '_fragment' => 'workers',
                ]),
                'inventory_jobs' => $this->generateUrl('frontend_dashboard', ['view' => 'queue', '_fragment' => 'inventory-jobs']),
                'sources' => $this->generateUrl('frontend_dashboard', ['view' => 'repositories']),
                'targets' => $this->generateUrl('settings_connections'),
                'inventory' => $this->generateUrl('assets'),
                'secrets' => $this->generateUrl('settings_secrets'),
                'policy' => $this->generateUrl('settings_policy'),
                'overview' => $this->generateUrl('overview'),
            ],
        ], $this->csrf('onboarding-discover', 'onboarding-scan'));
    }

    #[Route('/api/settings/getting-started', name: 'settings_getting_started_status', methods: ['GET'])]
    public function gettingStartedStatus(Request $request, WorkerPresence $workers): JsonResponse
    {
        return $this->json($this->gettingStartedSnapshot($workers, $request->query->getString('connection'), self::discoveryFilters($request->query))
            + ['csrf' => $this->csrf('onboarding-discover', 'onboarding-scan')],
            headers: ['Cache-Control' => 'private, no-store']);
    }

    private static function discoveryFilters(InputBag $input): array
    {
        $search = trim($input->getString('discovery_q'));
        $result = $input->getString('discovery_result');
        $job = $input->getString('discovery_job');
        $page = max(1, min(100000, $input->getInt('discovery_page', 1)));

        return ('' === $search ? [] : ['discovery_q' => $search])
            + (in_array($result, Connections::DISCOVERY_RESULTS, true) ? ['discovery_result' => $result] : [])
            + (in_array($job, Connections::DISCOVERY_JOB_STATES, true) ? ['discovery_job' => $job] : [])
            + ($input->getBoolean('discovery_credentials') ? ['discovery_credentials' => 1] : [])
            + ($page > 1 ? ['discovery_page' => $page] : []);
    }

    private function gettingStartedSnapshot(WorkerPresence $workers, string $selected, array $filters): array
    {
        $now = time();
        $connections = $this->store->db->fetchAllKeyValue('SELECT kind, COUNT(*) FROM inventory_connections GROUP BY kind');
        $sources = (int) ($connections['repository'] ?? 0);
        $search = $filters['discovery_q'] ?? '';
        $result = $filters['discovery_result'] ?? '';
        $job = $filters['discovery_job'] ?? '';
        $credentialsNeeded = isset($filters['discovery_credentials']);
        $page = $filters['discovery_page'] ?? 1;
        $pageSize = Connections::DISCOVERY_PAGE_SIZE;
        $pinned = [] === $filters ? $selected : '';
        $rows = $this->connections->discoveryChecklist($pinned, $search, $pageSize + 1, ($page - 1) * $pageSize, $result, $job, $credentialsNeeded);
        $visible = array_slice($rows, 0, $pageSize);
        $selection = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $selected) && !in_array($selected, array_column($visible, 'id'), true)
            ? ($this->connections->discoveryChecklist('', $selected, 1)[0] ?? null) : null;

        return [
            'checked_at' => $now,
            'transports' => $workers->recentTransports($now),
            'sources' => $sources,
            'targets' => array_sum($connections) - $sources,
            'assets' => (int) $this->store->db->fetchOne('SELECT COUNT(*) FROM assets'),
            'credential_managers' => (int) $this->store->db->fetchOne("SELECT COUNT(*) FROM operator_settings WHERE id LIKE 'manager:%'"),
            'discovery' => $visible,
            'discovery_selection' => $selection,
            'discovery_q' => $search,
            'discovery_result' => $result,
            'discovery_job' => $job,
            'discovery_credentials' => $credentialsNeeded,
            'discovery_page' => $page,
            'discovery_next' => count($rows) > $pageSize,
            'discovery_busy' => ($selection['busy'] ?? false) || $this->connections->hasActiveInventoryWork($search),
        ];
    }

    #[Route('/settings/connections', name: 'settings_connections', methods: ['GET'])]
    public function connections(Request $request): Response
    {
        $from = $request->query->all()['from'] ?? null;
        $connectionReturn = DashboardListContext::connectionSettings($from);
        $returnParameters = $connectionReturn ? ['from' => $connectionReturn['url']] : [];
        $filters = self::connectionFilters($request->query);
        $edit = $request->query->getString('edit');
        $editing = $edit !== '' ? $this->connections->get($edit) : null;
        if ('' !== $edit && !$editing) {
            $this->addFlash('error', 'That infrastructure connection could not be found.');

            return $this->redirectToRoute('settings_connections', $returnParameters + $filters + ['_fragment' => DashboardListContext::CONNECTIONS_SECTION]);
        }
        if ('cluster' === ($editing['kind'] ?? null)) {
            return $this->redirectToRoute('frontend_dashboard', ['view' => 'clusters', 'edit' => $editing['id']] + $returnParameters);
        }

        if ('repository' === ($editing['kind'] ?? null)) {
            return $this->redirectToRoute('frontend_dashboard', ['view' => 'repositories', 'edit' => $editing['id']] + $returnParameters);
        }
        $listUrl = $this->generateUrl('settings_connections', $returnParameters + $filters + ['_fragment' => DashboardListContext::CONNECTIONS_SECTION]);
        $list = $this->connections->settingsPage(
            $filters['connection_q'] ?? '', $filters['connection_kind'] ?? '', $filters['connection_state'] ?? '', $filters['connection_page'] ?? 1,
        );
        $queued = $request->query->getString('connection_job');
        $queued = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $queued) && !in_array($queued, array_column($list['rows'], 'id'), true)
            ? $this->connections->get($queued) : null;
        $linkAsset = $this->repositoryLinkChoice($request->query->getString('link_asset'), Inventory::repositoryLinkAssetKinds('deployment'));
        $relationship = $request->query->getString('relationship');
        if (!Inventory::repositoryLinkAssetKinds($relationship)) {
            $relationship = in_array($linkAsset['kind'] ?? 'image', ['workload', 'container'], true) ? 'deployment' : 'source';
        }
        if ($linkAsset && !in_array($linkAsset['kind'], Inventory::repositoryLinkAssetKinds($relationship), true)) {
            $linkAsset = null;
        }
        $linkRepository = $this->repositoryLinkChoice($request->query->getString('link_repository'), ['repository']);
        $linkReturn = DashboardListContext::assetDetail($from, [DashboardListContext::ASSET_RELATIONS_SECTION]);
        $linkView = null;
        if ($linkAsset && $linkRepository
            && ($edge = $this->inventory->repositoryLinkFingerprint($linkAsset['id'], $linkRepository['id'], $relationship))) {
            $assetPath = $this->generateUrl('asset', ['id' => $linkAsset['id']]);
            $base = $linkReturn && $assetPath === parse_url($linkReturn, PHP_URL_PATH) ? explode('#', $linkReturn, 2)[0] : $assetPath;
            $linkView = $base.'#'.DashboardListContext::ASSET_RELATION_PREFIX.$edge;
        }

        return $this->preact->render('settings-connections', [
            'connectionReturn' => $connectionReturn,
            'connectionSaveUrl' => $this->generateUrl('settings_connection_save_api'),
            'ansible_upload_limit' => AnsibleInventory::MAX_UPLOAD,
            'connection_filters' => $filters,
            'connection_list_url' => $listUrl,
            'connection_list_next' => $list['next'],
            'queued_connection_job' => $queued && Connections::hasInventoryJob($queued)
                ? ['name' => $queued['name'], 'url' => $this->connectionJobUrl($queued['id'], $listUrl)] : null,
            'connections' => array_map(fn (array $row): array => self::connectionView($row, [
                'target', 'port', 'ansible_groups', 'status', 'interval', 'result', 'operation', 'finished_at', 'argo_namespace',
            ]) + [
                'needs_credential' => Connections::needsManagedCredential($row),
                'has_argo_credential' => !empty($row['data']['argo_credential']),
                'linux_asset_url' => 'vm' === $row['kind'] && !empty($row['data']['last_discovery']['asset_id'])
                    ? $this->generateUrl('asset', ['id' => $row['data']['last_discovery']['asset_id']]) : null,
                'job_url' => Connections::hasInventoryJob($row) ? $this->connectionJobUrl($row['id'], $listUrl) : null,
            ], $list['rows']),
            'editing' => $editing ? self::connectionView($editing, [
                'target', 'port', 'docker_inventory', 'docker_sudo', 'package_updates', 'credential', 'context',
                'platform', 'role', 'infra_context', 'canonical_url', 'subdirectory', 'editable', 'interval',
            ]) : null,
            'editing_repository' => $this->repositoryLinkChoice($editing['data']['repository'] ?? '', ['repository']),
            'repository_picker' => $this->generateUrl('settings_inventory_picker'),
            'repository_link' => [
                'asset' => $linkAsset,
                'repository' => $linkRepository,
                'relationship' => $relationship,
                'return' => $linkReturn,
                'view' => $linkView,
                'asset_kinds' => [
                    'source' => Inventory::repositoryLinkAssetKinds('source'),
                    'built-from' => Inventory::repositoryLinkAssetKinds('built-from'),
                    'deployment' => Inventory::repositoryLinkAssetKinds('deployment'),
                ],
            ],
            'vault_destinations' => $this->managers->vaultDestinations(),
        ], $this->csrf('connection', 'run', 'remove', 'ansible-inventory', 'link', 'store-credential', 'manager-test'));
    }

    private static function connectionFilters(InputBag $input): array
    {
        $search = trim($input->getString('connection_q'));
        $kind = $input->getString('connection_kind');
        $state = $input->getString('connection_state');
        $page = max(1, min(100000, $input->getInt('connection_page', 1)));

        return ('' === $search ? [] : ['connection_q' => $search])
            + (in_array($kind, Connections::settingsKinds(), true) ? ['connection_kind' => $kind] : [])
            + (in_array($state, Connections::settingsJobStates(), true) ? ['connection_state' => $state] : [])
            + ($page > 1 ? ['connection_page' => $page] : []);
    }

    private function connectionJobUrl(string $id, string $from): string
    {
        return $this->generateUrl('frontend_dashboard', [
            'view' => 'queue', 'inventory_connection' => $id, 'from' => $from, '_fragment' => 'inventory-jobs/'.$id,
        ]);
    }

    #[Route('/api/settings/repository-link-assets', name: 'settings_repository_link_assets', methods: ['GET'])]
    #[Route('/api/settings/inventory-picker', name: 'settings_inventory_picker', methods: ['GET'])]
    public function inventoryPicker(Request $request): JsonResponse
    {
        $scope = $request->query->getString('scope');
        $kinds = in_array($scope, ['repository', 'linux'], true) ? [$scope] : Inventory::repositoryLinkAssetKinds($scope);
        $headers = ['Cache-Control' => 'private, no-store'];
        if (!$kinds) {
            return $this->json(['error' => 'Choose an inventory asset type or repository relationship.'], Response::HTTP_BAD_REQUEST, $headers);
        }
        $query = trim($request->query->getString('q'));
        $page = max(1, min(100000, $request->query->getInt('page', 1)));
        $params = [$kinds];
        $identity = $this->repositoryLinkIdentity();
        $filter = '';
        if (preg_match('/^[a-f0-9]{64}$/iD', $query)) {
            $filter = ' AND a.id = ?';
            $params[] = strtolower($query);
        } elseif ('' !== $query) {
            $filter = " AND (LOWER(a.name) LIKE LOWER(?) ESCAPE '!' OR LOWER($identity) LIKE LOWER(?) ESCAPE '!')";
            $pattern = '%'.strtr($query, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            array_push($params, $pattern, $pattern);
        }
        $limit = self::REPOSITORY_PICKER_LIMIT + 1;
        $offset = ($page - 1) * self::REPOSITORY_PICKER_LIMIT;
        $rows = $this->store->db->fetchAllAssociative("SELECT a.id, a.kind, a.name, $identity AS identity FROM assets a
            WHERE a.kind IN (?)$filter ORDER BY LOWER(a.name), a.kind, a.id LIMIT $limit OFFSET $offset", $params, [ArrayParameterType::STRING]);

        return $this->json(['rows' => array_slice($rows, 0, self::REPOSITORY_PICKER_LIMIT),
            'next' => count($rows) > self::REPOSITORY_PICKER_LIMIT], headers: $headers);
    }

    private function repositoryLinkIdentity(): string
    {
        $digest = $this->store->jsonText('a.data', 'digest');
        $subdirectory = $this->store->jsonText('a.data', 'subdirectory');
        $workloadScope = $this->store->jsonText('a.data', 'scope');
        $containerContext = $this->store->jsonText('a.data', 'context');
        $sshTarget = $this->store->jsonText('a.data', 'ssh_alias');

        return "CASE a.kind WHEN 'image' THEN $digest WHEN 'repository' THEN $subdirectory
            WHEN 'workload' THEN $workloadScope WHEN 'container' THEN $containerContext WHEN 'linux' THEN $sshTarget END";
    }

    private function repositoryLinkChoice(string $id, array $kinds): ?array
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $id)) {
            return null;
        }
        $identity = $this->repositoryLinkIdentity();

        return $this->store->db->fetchAssociative("SELECT a.id, a.kind, a.name, $identity AS identity FROM assets a
            WHERE a.id = ? AND a.kind IN (?)", [$id, $kinds], [ParameterType::STRING, ArrayParameterType::STRING]) ?: null;
    }

    #[Route('/settings/connection', name: 'settings_connection_save', methods: ['POST'], priority: 1)]
    #[Route('/api/settings/connection', name: 'settings_connection_save_api', methods: ['POST'])]
    public function saveConnection(Request $request): Response
    {
        $json = 'settings_connection_save_api' === $request->attributes->get('_route');
        $headers = ['Cache-Control' => 'private, no-store'];
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('settings-connection', $fields->getString('_token'))) {
            if ($json) {
                return $this->json(['error' => 'Your settings session expired. Reload Connections and try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN, $headers);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }
        $connectionReturn = DashboardListContext::connectionSettings($fields->all()['from'] ?? null);
        $parameters = ($connectionReturn ? ['from' => $connectionReturn['url']] : []) + self::connectionFilters($fields);
        try {
            $saved = $this->connections->save($fields->getString('kind'), $fields->all());
        } catch (\InvalidArgumentException|\DomainException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
            if ('' !== ($id = $fields->getString('id'))) {
                $parameters['edit'] = $id;
            }

            return $this->redirectToRoute('settings_connections', $parameters, Response::HTTP_SEE_OTHER);
        }
        if ('getting-started' === ($connectionReturn['kind'] ?? null)) {
            $origin = Request::create($connectionReturn['url']);
            $queueReturn = DashboardReturnPath::queueSection($origin->query->all()['from'] ?? null, 'inventory-jobs');
            $parameters['from'] = $this->generateUrl('settings_getting-started', [
                'connection' => $saved, '_fragment' => DashboardListContext::DISCOVERY_SECTION,
            ] + self::discoveryFilters($origin->query) + ($queueReturn ? ['from' => $queueReturn] : []));
        }
        $this->addFlash('success', 'Connection saved.');
        $parameters['_fragment'] = DashboardListContext::CONNECTIONS_SECTION;
        $redirect = $this->generateUrl('settings_connections', $parameters);

        return $json ? $this->json(['redirect' => $redirect], headers: $headers)
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    #[Route('/api/settings/connection-tokens', name: 'settings_connection_tokens', methods: ['GET'])]
    public function connectionTokens(Request $request): JsonResponse
    {
        $tokens = $this->csrf(
            'connection', 'manager-test', 'secrets-manager', 'store-credential',
            'jenkins-save', 'registry-auth', 'argo-save',
            'worker', 'scanner', 'scan-schedule', 'policy', 'rollout', 'ai',
            'ansible-inventory', 'ansible-vault', 'delivery-adopt', 'delivery-cloud',
        );
        if ('admin' === $request->attributes->get('_dashboard_role')) {
            $tokens['access-provider'] = $this->tokens->getToken(AuthDashboard::PROVIDER_EDIT_CSRF)->getValue();
            $tokens['access-users'] = $this->tokens->getToken(AccountApi::USERS_CSRF)->getValue();
        }

        return $this->json($tokens + [
            'binary-save' => $this->tokens->getToken('binary-save')->getValue(),
            'repository' => $this->tokens->getToken(RepositoryConnectionsApi::PURPOSE)->getValue(),
            'kubernetes' => $this->tokens->getToken(KubernetesConnectionsApi::CSRF)->getValue(),
        ], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/settings/secrets', name: 'settings_secrets', methods: ['GET'])]
    public function secrets(Request $request): Response
    {
        $managers = array_map(static fn (array $row): array => array_intersect_key($row['data'], array_flip([
            'name', 'type', 'scope', 'address', 'has_token', 'has_writer_token', 'bundles',
        ])), $this->managers->all());
        $alias = $request->query->getString('edit_manager');
        $editing = null;
        foreach ($managers as $manager) {
            if ($alias === $manager['name'] && isset(SecretManagers::TYPES[$manager['type']])) {
                $editing = $manager;
                break;
            }
        }

        return $this->preact->render('settings-secrets', [
            'managers' => $managers,
            'editing' => $editing,
            'ansible_upload_limit' => AnsibleVault::MAX_UPLOAD,
            'managerTypes' => SecretManagers::TYPES,
            'vault_destinations' => $this->managers->vaultDestinations(),
            'connectionReturn' => DashboardListContext::credentialSettings($request->query->all()['from'] ?? null),
        ], $this->csrf('secrets-manager', 'manager-remove', 'manager-test', 'ansible-vault', 'store-credential'));
    }

    #[Route('/api/settings/secrets/{action}', name: 'settings_secret_manager_action', requirements: [
        'action' => 'secrets-manager|manager-test',
    ], methods: ['POST'])]
    public function updateSecrets(string $action, Request $request, ConnectionCredentials $credentials, ManagedGit $git): JsonResponse
    {
        $headers = ['Cache-Control' => 'private, no-store'];
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('settings-'.$action, $fields->getString('_token'))) {
            return $this->json(['error' => 'Your Settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN, $headers);
        }
        try {
            $kind = 'manager-test' === $action ? $fields->getString('credential_kind') : '';
            $message = '' === $kind ? $this->applySecretAction($action, $request) : $this->checkConnectionCredential($fields, $kind, $credentials, $git);
        } catch (\InvalidArgumentException|\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        }
        if ('manager-test' === $action) {
            return $this->json(['message' => $message], headers: $headers);
        }
        $this->addFlash('success', $message);
        $context = DashboardListContext::credentialSettings($fields->all()['from'] ?? null);
        $redirect = $this->generateUrl('settings_secrets', ['_fragment' => 'secrets-manager'] + ($context ? ['from' => $context['url']] : []));

        return $this->json(['redirect' => $redirect], headers: $headers);
    }

    private function checkConnectionCredential(InputBag $fields, string $kind, ConnectionCredentials $credentials, ManagedGit $git): string
    {
        $reference = trim($fields->getString('reference'));
        $target = trim($fields->getString('target'));
        match ($kind) {
            'ssh' => $credentials->checkSshReference($reference, '' === $target ? null : $target),
            'git' => $git->credentials($reference, $target),
            'kubeconfig' => $credentials->checkKubernetesReference($reference, '' === $target ? null : $target),
            default => throw new \DomainException('Choose a supported connection credential type.'),
        };

        return 'The credential bundle passed validation.';
    }

    private function applySecretAction(string $action, Request $request): string
    {
        $fields = $request->request;
        if ('manager-test' === $action) {
            $this->managers->bundle(trim($fields->getString('reference')));

            return 'The secrets manager returned a credential bundle.';
        }
        $this->managers->save(
            trim($fields->getString('name')), $fields->getString('provider'), trim($fields->getString('scope')),
            trim($fields->getString('address')), trim($fields->getString('vault_token')),
            trim($fields->getString('vault_writer_token')), $fields->getBoolean('clear_vault_writer'),
        );

        return 'Secrets manager saved.';
    }

    #[Route('/settings/integrations', name: 'settings_integrations', methods: ['GET'])]
    public function integrations(Request $request): Response
    {
        $servers = array_column(array_map(static fn (array $row): array => array_intersect_key($row, array_flip([
            'server', 'reference',
        ])), $this->jenkins->all()), null, 'server');
        ksort($servers);
        $registries = [];
        foreach ($this->operator->registries() as $host) {
            $registries[$host] = $this->operator->registryReference($host);
        }
        ksort($registries);
        $registry = OperatorSettings::normalizeRegistryHost($request->query->getString('registry'));
        $requestedReturn = $request->query->all()['from'] ?? null;
        $releaseReturn = DashboardListContext::remediationDetail($requestedReturn, DashboardListContext::RELEASE_TRACKING_SECTION);
        $discoveryReturn = DashboardListContext::deliveryCandidate($requestedReturn);
        $from = DashboardListContext::kubernetesDirectory($requestedReturn) ?? $releaseReturn ?? $discoveryReturn;
        $jenkinsServer = JenkinsConnections::normalizeServer($request->query->getString('jenkins'));
        $filters = self::argoFilters($request->query);
        $clusters = $this->connections->settingsPage($filters['argo_q'] ?? '', 'cluster', '', $filters['argo_page'] ?? 1);
        $clusterId = $request->query->getString('argo_cluster');
        $selected = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $clusterId) ? $this->connections->get($clusterId) : null;
        $selected = 'cluster' === ($selected['kind'] ?? null) ? $selected : null;
        $session = $request->hasSession() ? $request->getSession() : null;
        $draft = $session?->get(self::ARGO_DRAFT);
        if ($selected && $clusterId === ($draft['cluster'] ?? null)) {
            $session->remove(self::ARGO_DRAFT);
        } else {
            $draft = null;
        }
        $argoUrl = $this->generateUrl('settings_integrations', ['argo_cluster' => $clusterId, '_fragment' => DashboardListContext::ARGO_SECTION]
            + ($from ? ['from' => $from] : []) + $filters);

        return $this->preact->render('settings-integrations', [
            'jenkins' => $servers,
            'editJenkins' => $jenkinsServer ? ($servers[$jenkinsServer] ?? null) : null,
            'suggestedJenkinsServer' => $jenkinsServer,
            'release_return' => $releaseReturn,
            'discovery_return' => $discoveryReturn,
            'registries' => $registries,
            'editRegistry' => null !== $registry && array_key_exists($registry, $registries) ? ['host' => $registry, 'reference' => $registries[$registry]] : null,
            'suggestedRegistryHost' => $registry,
            'argo_filters' => $filters,
            'argo_clusters' => array_map(self::argoClusterView(...), $clusters['rows']),
            'argo_next' => $clusters['next'],
            'argo_return' => $from,
            'argo_missing' => '' !== $clusterId && !$selected,
            'argo_selected' => $selected ? self::argoClusterView($selected) + [
                'reference' => SecretManagers::validReference($selected['data']['argo_credential'] ?? '') ? $selected['data']['argo_credential'] : '',
                'worker_kubeconfig' => 'worker' === ($selected['data']['credential_mode'] ?? null)
                    && '' === Connections::argoCredential($selected['data']),
                'job_url' => 'argo' === ($selected['data']['operation'] ?? null) && Connections::hasInventoryJob($selected)
                    ? $this->connectionJobUrl($clusterId, $argoUrl) : null,
            ] : null,
            'argo_draft' => $draft,
            'vault_destinations' => $this->managers->vaultDestinations(),
        ], $this->csrf('jenkins-save', 'jenkins-remove', 'registry-auth', 'registry-remove', 'argo-save', 'argo-read', 'store-credential'));
    }

    private static function argoFilters(InputBag $input): array
    {
        $query = trim($input->getString('argo_q'));
        $page = max(1, min(100000, $input->getInt('argo_page', 1)));

        return ('' === $query ? [] : ['argo_q' => $query]) + ($page > 1 ? ['argo_page' => $page] : []);
    }

    private static function argoClusterView(array $row): array
    {
        $data = $row['data'];
        $namespace = $data['argo_namespace'] ?? '';
        $access = match (true) {
            '' === $namespace => 'off',
            !SecretManagers::validReference(Connections::argoCredential($data)) => 'needs_credential',
            !empty($data['argo_credential']) => 'dedicated',
            default => 'cluster',
        };

        return ['id' => $row['id'], 'name' => $row['name'], 'target' => $data['target'] ?? '', 'namespace' => $namespace, 'access' => $access];
    }

    #[Route('/settings/providers', name: 'settings_providers', methods: ['GET'])]
    public function providers(Compatibility $ai, CodexFixture $codex): Response
    {
        $settings = $ai->settings();
        $settings['endpoint'] = self::publicUrl($settings['endpoint']);

        return $this->preact->render('settings-providers', [
            'ai' => $settings,
            'codex_available' => $codex->available(),
            'vault_destinations' => $this->managers->vaultDestinations(),
        ], $this->csrf('ai', 'store-credential'));
    }

    #[Route('/settings/scanning', name: 'settings_scanning', methods: ['GET'])]
    public function scanning(Request $request, Sandbox $sandbox, Scanner $scanner, SchedulerActivity $activity): Response
    {
        $now = time();
        $from = $request->query->all()['from'] ?? null;
        $filters = $this->scanSettingsFilters($request->query);
        $schedules = $this->scans->settingsPage($filters['schedule_q'] ?? '', $filters['schedule_page'] ?? 1, true);
        $schedules['rows'] = array_map(static fn (array $row): array => self::scanSettingsRow($row, $now), $schedules['rows']);
        $selected = $this->scans->settingsTarget($request->query->getString('asset'));
        $queueReturn = DashboardReturnPath::queueSection($from);
        $assetReturn = DashboardListContext::scanSettingsAssetReturn($from);
        $trackScan = null;
        if (isset($selected['interval_seconds']) && null === $queueReturn) {
            $id = $selected['id'];
            $target = ['asset' => $id, '_fragment' => DashboardListContext::RECURRING_SCANS_SECTION];
            $editor = $this->generateUrl('settings_scanning', $target + ($assetReturn ? ['from' => $assetReturn] : []) + $filters);
            $trackScan = $this->generateUrl('frontend_dashboard', [
                'view' => 'queue', 'scan_target' => 'asset', 'scan_q' => $id, '_fragment' => 'scheduled-scans/asset/'.$id,
                'from' => DashboardReturnPath::validate($editor)
                    ?? DashboardReturnPath::validate($this->generateUrl('settings_scanning', $target + $filters))
                    ?? $this->generateUrl('settings_scanning', $target),
            ]);
        }

        return $this->preact->render('settings-scanning', [
            'queueReturn' => $queueReturn,
            'assetReturn' => $assetReturn,
            'track_scan' => $trackScan,
            'worker' => array_intersect_key($sandbox->settings(), ['image' => true, 'network' => true]),
            'scanner' => $scanner->settings(),
            'scan_scheduler' => $activity->latest(SchedulerActivity::SCANS),
            'scan_targets' => $this->scans->settingsPage($filters['asset_q'] ?? '', $filters['asset_page'] ?? 1, false),
            'selected_scan_target' => $selected ? self::scanSettingsRow($selected, $now) : null,
            'draft_interval' => $request->query->has('minutes') ? $request->query->getInt('minutes') : null,
            'scan_settings_view' => $schedules,
        ], $this->csrf('worker', 'scanner', 'scan-schedule', 'scan-retry', 'scan-remove'));
    }

    private static function scanSettingsRow(array $row, int $now): array
    {
        return ['id' => $row['id'], 'name' => $row['name'], 'kind' => $row['kind']]
            + (null === $row['interval_seconds'] ? [] : [
                'interval_seconds' => (int) $row['interval_seconds'], 'next_at' => (int) $row['next_at'],
                'state' => $row['lease_until'] > $now ? 'running' : ($row['next_at'] <= $now ? 'due' : 'scheduled'),
                'outcome' => $row['data']['outcome'] ?? null, 'attempted_at' => $row['data']['attempted_at'] ?? null,
                'failure_reason' => $row['data']['failure_reason'] ?? null,
            ]);
    }

    private function scanSettingsFilters(InputBag $input): array
    {
        $filters = [];
        foreach (['asset', 'schedule'] as $list) {
            $search = trim($input->getString($list.'_q'));
            $page = max(1, min(100000, $input->getInt($list.'_page', 1)));
            if ('' !== $search) {
                $filters[$list.'_q'] = $search;
            }
            if ($page > 1) {
                $filters[$list.'_page'] = $page;
            }
        }

        return $filters;
    }

    #[Route('/settings/policy', name: 'settings_policy', methods: ['GET'])]
    public function policy(Request $request): Response
    {
        $filters = self::policyFilters($request->query) + ['policy_q' => '', 'policy_scope' => '', 'policy_page' => 1];
        $repository = $this->approvals->repository($request->query->getString('repository'));
        $policies = $this->approvals->repositoryPage($filters['policy_q'], $filters['policy_scope'], $filters['policy_page']);
        $from = $request->query->all()['from'] ?? null;
        $rolloutChange = $request->query->getString('rollout_change');
        if (!preg_match('/^[a-f0-9]{24}$/D', $rolloutChange)) {
            $rolloutChange = '';
        }
        $session = $request->hasSession() ? $request->getSession() : null;
        $draft = $session?->get(self::ROLLOUT_DRAFT);
        if (($draft['change'] ?? null) === $rolloutChange) {
            $session->remove(self::ROLLOUT_DRAFT);
        } else {
            $draft = null;
        }

        return $this->preact->render('settings-policy', [
            'policy_filters' => $filters,
            'policy_return' => DashboardListContext::policySettings($from),
            'selected_repository' => $repository ? self::repositoryPolicyView($repository) : null,
            'policy_results' => ['rows' => array_map(self::repositoryPolicyView(...), $policies['rows']), 'next' => $policies['next']],
            'rollout_change' => $rolloutChange,
            'rollout_draft' => $draft,
            'rollouts' => array_map(self::rolloutScheduleView(...), $this->rollouts->history()),
            'staged' => $this->rollouts->changesForScheduling(),
            'canaries' => $this->rollouts->canaries(),
        ], $this->csrf('policy', 'rollout', 'rollout-cancel'));
    }

    private static function rolloutScheduleView(array $row): array
    {
        return array_intersect_key($row, array_flip([
            'id', 'status', 'not_before', 'lease_until', 'title', 'canary_title', 'canary_status', 'canary_schedule_status',
        ]))
            + array_intersect_key($row['data'], array_flip(['service', 'context', 'canary', 'last_error']));
    }

    private static function policyFilters(InputBag $input): array
    {
        $search = trim($input->getString('policy_q'));
        $scope = $input->getString('policy_scope');
        $page = max(1, min(100000, $input->getInt('policy_page', 1)));

        return ('' === $search ? [] : ['policy_q' => $search])
            + (in_array($scope, ['default', 'custom'], true) ? ['policy_scope' => $scope] : [])
            + ($page > 1 ? ['policy_page' => $page] : []);
    }

    private static function repositoryPolicyView(array $row): array
    {
        return [
            'id' => $row['id'], 'name' => $row['name'], 'custom' => null !== $row['data'],
            'strategies' => $row['data']['strategies'] ?? [], 'independent' => $row['data']['independent'] ?? false,
        ];
    }

    private static function connectionView(array $row, array $fields): array
    {
        $data = array_intersect_key($row['data'], array_flip($fields));
        if ('repository' === $row['kind']) {
            foreach (['target', 'canonical_url'] as $field) {
                if (isset($data[$field])) {
                    $data[$field] = self::publicUrl($data[$field]);
                }
            }
        }
        foreach (['credential', 'argo_credential'] as $field) {
            if (isset($data[$field]) && !SecretManagers::validReference($data[$field])) {
                unset($data[$field]);
            }
        }

        return ['id' => $row['id'], 'kind' => $row['kind'], 'name' => $row['name'], 'data' => $data];
    }

    private static function publicUrl(string $value): string
    {
        if (!str_contains($value, '://')) {
            return $value;
        }
        $parts = parse_url($value);
        if (false === $parts || array_intersect_key($parts, array_flip(['user', 'pass', 'query', 'fragment']))) {
            return Repository::safeUrl($value);
        }

        return $value;
    }

    private function csrf(string ...$actions): array
    {
        $tokens = [];
        foreach ($actions as $action) {
            $tokens[$action] = $this->tokens->getToken('settings-'.$action)->getValue();
        }

        return $tokens;
    }

    #[Route('/settings/models', name: 'settings_models', methods: ['POST'], priority: 10)]
    #[Route('/api/settings/providers/models', name: 'settings_models_api', methods: ['POST'])]
    public function models(Request $request, Compatibility $ai, ModelDiscovery $models): Response
    {
        $fields = $request->request;
        $headers = ['Cache-Control' => 'private, no-store'];
        if (!$this->isCsrfTokenValid('settings-ai', $fields->getString('_token'))) {
            if ('settings_models_api' === $request->attributes->get('_route')) {
                return $this->json(['error' => 'Your settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN, $headers);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }

        try {
            $provider = $fields->getString('provider');
            $model = $fields->getString('model');
            $key = 'openai' === $provider && '' === $model ? ($fields->getString('discovery_key') ?: $ai->openAiKey()) : '';

            return $this->json($models->discover($provider, $fields->getString('endpoint'), $key, $model), headers: $headers);
        } catch (\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        } catch (\Throwable) {
            return $this->json(['error' => 'Provider model discovery failed.'], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        }
    }

    #[Route('/settings/credentials', name: 'settings_store_credential', methods: ['POST'], priority: 10)]
    #[Route('/api/settings/credentials', name: 'settings_store_credential_api', methods: ['POST'])]
    public function storeCredential(Request $request): Response
    {
        $fields = $request->request;
        $headers = ['Cache-Control' => 'private, no-store'];
        if (!$this->isCsrfTokenValid('settings-store-credential', $fields->getString('_token'))) {
            return $this->json(['error' => 'Your settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN, $headers);
        }

        try {
            $reference = $this->managers->storeVaultBundle($fields->getString('manager'), $fields->getString('bundle'));

            return $this->json(['reference' => $reference], Response::HTTP_CREATED, $headers);
        } catch (\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        }
    }

    #[Route('/settings/{action}', name: 'settings_update', methods: ['POST'])]
    #[Route('/api/settings/integrations/{action}', name: 'settings_integration_save_api', requirements: [
        'action' => 'jenkins-save|registry-auth|argo-save',
    ], methods: ['POST'])]
    #[Route('/api/settings/operations/{action}', name: 'settings_operations_save_api', requirements: [
        'action' => 'worker|scanner|scan-schedule|policy|rollout|ansible-inventory|ansible-vault',
    ], methods: ['POST'])]
    #[Route('/api/settings/providers/ai', name: 'settings_provider_save_api', defaults: ['action' => 'ai'], methods: ['POST'])]
    public function update(string $action, Request $request, AnsibleInventory $ansible): Response
    {
        $json = in_array($request->attributes->get('_route'), ['settings_integration_save_api', 'settings_operations_save_api', 'settings_provider_save_api'], true);
        $headers = ['Cache-Control' => 'private, no-store'];
        if (!$this->isCsrfTokenValid('settings-'.$action, $request->request->getString('_token'))) {
            if ($json) {
                return $this->json(['error' => 'Your settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'], Response::HTTP_FORBIDDEN, $headers);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }
        $route = match ($action) {
            'run', 'remove', 'link', 'ansible-inventory' => 'settings_connections',
            'onboarding-discover', 'onboarding-scan' => 'settings_getting-started',
            'secrets-manager', 'manager-remove', 'manager-test', 'ansible-vault' => 'settings_secrets',
            'jenkins-save', 'jenkins-remove', 'registry-auth', 'registry-remove', 'argo-save', 'argo-read' => 'settings_integrations',
            'ai' => 'settings_providers',
            'worker', 'scanner', 'scan-schedule', 'scan-retry', 'scan-remove' => 'settings_scanning',
            'policy', 'rollout', 'rollout-cancel' => 'settings_policy',
            default => throw $this->createNotFoundException(),
        };

        $fields = $request->request;
        $scanReturn = 'scan-retry' === $action || ('run' === $action && 'scan' === $fields->getString('operation'))
            ? DashboardReturnPath::queueSection($fields->all()['return'] ?? null) : null;
        if ('scan-retry' === $action && $request->query->getBoolean('return_to_asset')
            && preg_match('/^[a-f0-9]{64}$/D', $assetId = $fields->getString('id'))) {
            $scanReturn = $this->generateUrl('asset', ['id' => $assetId, '_fragment' => 'scan-failure'] + DashboardListContext::asset($request));
        }
        $returnParameters = [];
        $requestedReturn = $fields->all()['from'] ?? null;
        $connectionReturn = 'settings_connections' === $route ? DashboardListContext::connectionSettings($requestedReturn) : null;
        if ($connectionReturn) {
            $returnParameters['from'] = $connectionReturn['url'];
        } elseif ('settings_secrets' === $route && ($credentialReturn = DashboardListContext::credentialSettings($requestedReturn))) {
            $returnParameters['from'] = $credentialReturn['url'];
        } elseif ('settings_scanning' === $route) {
            $scanningReturn = DashboardReturnPath::queueSection($requestedReturn) ?? DashboardListContext::scanSettingsAssetReturn($requestedReturn);
            if (null !== $scanningReturn) {
                $returnParameters['from'] = $scanningReturn;
            }
        } elseif ('settings_policy' === $route && ($policyReturn = DashboardListContext::policySettings($requestedReturn))) {
            $returnParameters['from'] = $policyReturn['url'];
        }
        if ('settings_connections' === $route) {
            $returnParameters += self::connectionFilters($fields);
            if ('link' !== $action) {
                $returnParameters['_fragment'] = DashboardListContext::CONNECTIONS_SECTION;
            }
        } elseif ('ansible-vault' === $action) {
            $returnParameters['_fragment'] = 'secrets-manager';
        }
        if ('settings_getting-started' === $route) {
            $returnParameters = ['connection' => $fields->getString('id'), '_fragment' => DashboardListContext::DISCOVERY_SECTION]
                + self::discoveryFilters($fields);
            if ($inventoryReturn = DashboardReturnPath::queueSection($requestedReturn, 'inventory-jobs')) {
                $returnParameters['from'] = $inventoryReturn;
            }
        } elseif (in_array($action, ['scan-schedule', 'scan-retry', 'scan-remove'], true)) {
            $fragment = 'scan-schedule' === $action ? DashboardListContext::RECURRING_SCANS_SECTION : DashboardListContext::SAVED_SCAN_SCHEDULES_SECTION;
            if ('scan-retry' === $action && preg_match('/^[a-f0-9]{64}$/D', $schedule = $fields->getString('id'))) {
                $fragment = DashboardListContext::SAVED_SCAN_SCHEDULE_PREFIX.$schedule;
            }
            $returnParameters += ['_fragment' => $fragment] + $this->scanSettingsFilters($fields);
        } elseif (in_array($action, ['worker', 'scanner'], true)) {
            $returnParameters += ['_fragment' => 'scanner-worker'] + $this->scanSettingsFilters($fields);
            if (preg_match('/^[a-f0-9]{64}$/D', $asset = $fields->getString('asset'))) {
                $returnParameters['asset'] = $asset;
            }
        } elseif ('link' === $action) {
            $returnParameters += ['_fragment' => 'repository-links', 'link_asset' => $fields->getString('asset'),
                'link_repository' => $fields->getString('repository'), 'relationship' => $fields->getString('relationship')];
            if ($assetReturn = DashboardListContext::assetDetail($requestedReturn, [DashboardListContext::ASSET_RELATIONS_SECTION])) {
                $returnParameters['from'] = $assetReturn;
            }
        } elseif ('policy' === $action) {
            $returnParameters += ['_fragment' => DashboardListContext::APPROVAL_POLICY_EDITOR_SECTION] + self::policyFilters($fields);
            if (preg_match('/^[a-f0-9]{24}$/D', $rolloutChange = $fields->getString('rollout_change'))) {
                $returnParameters['rollout_change'] = $rolloutChange;
            }
        } elseif ('ai' === $action) {
            $returnParameters['_fragment'] = 'provider-configuration';
        } elseif (in_array($action, ['argo-save', 'argo-read'], true)) {
            $returnParameters = ['argo_cluster' => $fields->getString('id'), '_fragment' => DashboardListContext::ARGO_SECTION] + self::argoFilters($fields);
            $argoReturn = DashboardListContext::kubernetesDirectory($requestedReturn)
                ?? DashboardListContext::remediationDetail($requestedReturn, DashboardListContext::RELEASE_TRACKING_SECTION)
                ?? DashboardListContext::deliveryCandidate($requestedReturn);
            if ($argoReturn) {
                $returnParameters['from'] = $argoReturn;
            }
        } elseif ('settings_integrations' === $route) {
            $jenkins = str_starts_with($action, 'jenkins-');
            $returnParameters['_fragment'] = $jenkins ? 'jenkins' : 'harbor';
            if ($integrationReturn = DashboardListContext::remediationDetail($requestedReturn, DashboardListContext::RELEASE_TRACKING_SECTION)
                ?? DashboardListContext::deliveryCandidate($requestedReturn)) {
                $returnParameters['from'] = $integrationReturn;
                if ('jenkins-save' === $action && ($server = JenkinsConnections::normalizeServer($fields->getString('server')))) {
                    $returnParameters['jenkins'] = $server;
                }
                if ('registry-auth' === $action && null !== ($host = OperatorSettings::normalizeRegistryHost($fields->getString('host')))) {
                    $returnParameters['registry'] = $host;
                }
            }
        } elseif (in_array($action, ['rollout', 'rollout-cancel'], true)) {
            $returnParameters += ['_fragment' => 'rollout-schedules', 'rollout_change' => $fields->getString('change')] + self::policyFilters($fields);
            if (preg_match('/^[a-f0-9]{64}$/D', $repository = $fields->getString('repository'))) {
                $returnParameters['repository'] = $repository;
            }
        }
        $success = 'Settings saved.';
        try {
            switch ($action) {
                case 'ai':
                    $this->operator->saveAi($fields->all());
                    $success = 'AI settings saved.';
                    break;
                case 'worker':
                    $this->operator->saveWorker($fields->all());
                    $success = 'Worker settings saved.';
                    break;
                case 'scanner':
                    $this->operator->saveScanner($fields->getInt('timeout'));
                    $success = 'Scanner settings saved.';
                    break;
                case 'jenkins-save':
                    $this->jenkins->save($fields->getString('server'), $fields->getString('reference'));
                    break;
                case 'jenkins-remove':
                    $this->jenkins->remove($fields->getString('server'));
                    break;
                case 'argo-save':
                    $this->connections->saveArgo($fields->getString('id'), $fields->getString('namespace'), $fields->getString('reference'));
                    $success = 'Argo CD settings saved.';
                    break;
                case 'argo-read':
                    $this->connections->run($fields->getString('id'), 'argo');
                    $success = 'Argo CD discovery queued.';
                    break;
                case 'registry-auth':
                    $this->operator->saveRegistryReference($fields->getString('host'), $fields->getString('reference'));
                    break;
                case 'registry-remove':
                    $this->operator->removeRegistry($fields->getString('host'));
                    break;
                case 'secrets-manager':
                case 'manager-test':
                    $success = $this->applySecretAction($action, $request);
                    break;
                case 'manager-remove':
                    $this->managers->remove($fields->getString('name'));
                    break;
                case 'ansible-vault':
                    $count = $this->managers->importAnsible(
                        trim($fields->getString('name')), trim($fields->getString('password_reference')),
                        $this->ansibleUpload($request, AnsibleVault::MAX_UPLOAD), $fields->getString('mapping'),
                    );
                    $success = sprintf('Imported Ansible Vault with %d credential %s.', $count, 1 === $count ? 'bundle' : 'bundles');
                    break;
                case 'ansible-inventory':
                    $inventory = $ansible->read(
                        $this->ansibleUpload($request, AnsibleInventory::MAX_UPLOAD), trim($fields->getString('ssh_user')),
                        trim($fields->getString('credential')), trim($fields->getString('group')),
                    );
                    $added = $this->connections->importAnsibleVms($inventory['hosts']);
                    $success = sprintf(
                        'Imported %d VM %s. %d already existed and %d had unsupported or incomplete SSH settings.',
                        $added, 1 === $added ? 'connection' : 'connections', count($inventory['hosts']) - $added, $inventory['skipped'],
                    );
                    break;
                case 'run':
                    $id = $fields->getString('id');
                    $this->connections->run($id, $fields->getString('operation'));
                    $returnParameters['connection_job'] = $id;
                    $success = $scanReturn ? 'Scan queued.' : 'Inventory job queued.';
                    break;
                case 'onboarding-discover':
                    $this->connections->run($fields->getString('id'), 'discover');
                    $success = 'Discovery requested.';
                    break;
                case 'onboarding-scan':
                    $this->connections->run($fields->getString('id'), 'scan', afterDiscovery: true);
                    $success = 'Scan queued.';
                    break;
                case 'remove':
                    $this->connections->remove($fields->getString('id'));
                    $success = 'Connection removed.';
                    break;
                case 'scan-schedule':
                    $this->scans->add($fields->getString('asset'), $fields->getInt('minutes'));
                    $success = 'Scan schedule saved.';
                    break;
                case 'scan-remove':
                    $this->scans->remove($fields->getString('asset'));
                    $success = 'Scan schedule removed.';
                    break;
                case 'scan-retry':
                    $success = $this->scans->requestRetry($fields->getString('id'))
                        ? 'Scan due for retry. The scan scheduler will pick it up.'
                        : 'This scan is already due for retry.';
                    break;
                case 'policy':
                    $this->approvals->configure($fields->getString('repository'), $fields->all('strategies'), $fields->getBoolean('independent'));
                    $success = 'Approval policy saved.';
                    break;
                case 'link':
                    $this->inventory->associateRepository($fields->getString('asset'), $fields->getString('repository'), $fields->getString('relationship'));
                    $success = 'Repository linked.';
                    break;
                case 'rollout':
                    $input = preg_replace('/Z$/D', '+00:00', $fields->getString('not_before'));
                    $time = \DateTimeImmutable::createFromFormat(DATE_ATOM, $input);
                    if (!$time || $time->format(DATE_ATOM) !== $input) {
                        throw new \DomainException('Use a timestamp with an explicit offset, such as 2026-11-21T12:00:00+01:00.');
                    }
                    $this->rollouts->add($fields->getString('change'), $fields->getString('previous'), $fields->getString('replacement'), $time, $fields->getString('canary') ?: null);
                    $success = 'Docker rollout scheduled.';
                    break;
                case 'rollout-cancel':
                    $this->rollouts->cancel($fields->getString('change'));
                    $success = 'Docker rollout canceled.';
                    break;
            }
            $this->addFlash('success', $success);
            if ($scanReturn) {
                return $this->redirect($scanReturn, Response::HTTP_SEE_OTHER);
            }

            $parameters = match ($action) {
                'policy' => ['repository' => $fields->getString('repository')],
                'scan-schedule' => ['asset' => $fields->getString('asset')],
                default => [],
            };

            if ($json) {
                return $this->json(['redirect' => $this->generateUrl($route, $parameters + $returnParameters)], headers: $headers);
            }
            return $this->redirectToRoute($route, $parameters + $returnParameters, Response::HTTP_SEE_OTHER);
        } catch (\InvalidArgumentException|\DomainException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            if ($json) {
                return $this->json(['error' => 'The local infrastructure command failed. Check its configured access.'], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', 'The local infrastructure command failed. Check its configured access.');
        }
        if ($scanReturn) {
            return $this->redirect($scanReturn, Response::HTTP_SEE_OTHER);
        }
        if ('jenkins-save' === $action && ($server = JenkinsConnections::normalizeServer($fields->getString('server')))) {
            $returnParameters['jenkins'] = $server;
        }
        if ('registry-auth' === $action && null !== ($host = OperatorSettings::normalizeRegistryHost($fields->getString('host')))) {
            $returnParameters['registry'] = $host;
        }
        if ('argo-save' === $action) {
            $reference = trim($fields->getString('reference'));
            $request->getSession()->set(self::ARGO_DRAFT, [
                'cluster' => $fields->getString('id'), 'namespace' => substr($fields->getString('namespace'), 0, 256),
                'reference' => ('' === $reference || SecretManagers::validReference($reference)) ? $reference : null,
            ]);
        }
        if ('rollout' === $action) {
            $draft = [];
            foreach (['change', 'previous', 'replacement', 'not_before', 'canary'] as $field) {
                $draft[$field] = substr($fields->getString($field), 0, 256);
            }
            $request->getSession()->set(self::ROLLOUT_DRAFT, $draft);
        }
        if (in_array($action, ['ansible-inventory', 'ansible-vault'], true)) {
            $returnParameters['_fragment'] = $action;
        }

        $parameters = match (true) {
            'secrets-manager' === $action && $fields->getBoolean('editing') => ['edit_manager' => $fields->getString('name')],
            'scan-schedule' === $action => ['asset' => $fields->getString('asset'), 'minutes' => $fields->getInt('minutes')],
            'policy' === $action => ['repository' => $fields->getString('repository')],
            default => [],
        };

        return $this->redirectToRoute($route, $parameters + $returnParameters, Response::HTTP_SEE_OTHER);
    }

    private function ansibleUpload(Request $request, int $limit): string
    {
        $file = $request->files->get('file');
        if (!$file instanceof UploadedFile || !$file->isValid() || $file->getSize() > $limit) {
            throw new \DomainException('Choose an Ansible file of 512 KiB or less.');
        }

        return $file->getContent();
    }
}
