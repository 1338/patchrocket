<?php
declare(strict_types=1);

namespace App\Controller;

use App\Discovery\CloudDeliveryDiscovery;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\DeliveryDiscovery;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\InputBag;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class DeliveryDiscoveryDashboard extends AbstractController
{
    private const PAGE_SIZE = 25;
    private const PRIVATE_RESPONSE = ['Cache-Control' => 'private, no-store'];

    public function __construct(
        private readonly DeliveryDiscovery $discovery,
        private readonly Connections $connections,
        private readonly JenkinsConnections $jenkins,
        private readonly OperatorSettings $operator,
        private readonly SecretManagers $managers,
        private readonly PreactPage $preact,
        private readonly CsrfTokenManagerInterface $tokens,
    ) {
    }

    #[Route('/settings/discovery', name: 'settings_discovery', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $candidates = $this->discovery->all();
        $connections = $this->connections->all();
        $selection = $request->query->getString('adopt');
        $selected = $candidates[$selection] ?? null;
        $clusterId = $selected['binding']['connection_id'] ?? array_key_first($selected['cluster_sources'] ?? []);
        $selectedCluster = 'argocd' === ($selected['kind'] ?? null) && null !== $clusterId ? $this->connections->get($clusterId) : null;
        $filterQuery = self::candidateFilters($request->query);
        $sourceQuery = self::sourceFilters($request->query);
        $filters = $filterQuery + ['candidate_q' => '', 'candidate_kind' => '', 'candidate_source' => '', 'candidate_page' => 1];
        $sourceFilters = $sourceQuery + ['source_q' => '', 'source_kind' => '', 'source_page' => 1];
        $search = $filters['candidate_q'];
        $kind = $filters['candidate_kind'];
        $source = $filters['candidate_source'];
        $filtered = array_filter($candidates, static fn (array $candidate): bool => ('' === $kind || $kind === $candidate['kind'])
            && ('' === $source || array_key_exists($source, $candidate['sources']))
            && ('' === $search || mb_stripos(implode("\n", [
                $candidate['label'], $candidate['endpoint'], $candidate['evidence'], $candidate['id'], DeliveryDiscovery::TYPES[$candidate['kind']],
                ...array_keys($candidate['sources']),
            ]), $search) !== false));
        $pageRows = array_slice($filtered, ($filters['candidate_page'] - 1) * self::PAGE_SIZE, self::PAGE_SIZE + 1);
        $visible = array_slice($pageRows, 0, self::PAGE_SIZE);
        $connectionIndex = array_column($connections, null, 'id');
        $servers = array_fill_keys(array_column($this->jenkins->all(), 'server'), true);
        $registries = array_fill_keys($this->operator->registries(), true);
        $sources = [];
        $observedSources = [];
        foreach ($candidates as $candidate) {
            foreach (array_keys($candidate['sources']) as $label) {
                $observedSources[$label] = true;
            }
        }
        foreach ($connections as $entry) {
            if (self::matchesSource($entry, $sourceFilters['source_kind'], $sourceFilters['source_q'])) {
                $sources[] = $entry;
            }
        }
        $sourceRows = array_slice($sources, ($sourceFilters['source_page'] - 1) * self::PAGE_SIZE, self::PAGE_SIZE + 1);
        $csrf = [];
        foreach (['delivery-adopt', 'delivery-queue', 'delivery-cloud', 'store-credential'] as $action) {
            $csrf[$action] = $this->tokens->getToken('settings-'.$action)->getValue();
        }

        return $this->preact->render('settings-discovery', [
            'candidates' => array_values(array_map(fn (array $candidate): array => self::candidateView($candidate)
                + $this->savedConnection($candidate, $filterQuery + $sourceQuery, $connectionIndex, $servers, $registries), $visible)),
            'candidate_filters' => $filters,
            'candidate_next' => count($pageRows) > self::PAGE_SIZE,
            'types' => DeliveryDiscovery::TYPES,
            'selected' => $selected ? self::candidateView($selected) : null,
            'selection_missing' => '' !== $selection && !$selected,
            'selected_cluster' => 'cluster' === ($selectedCluster['kind'] ?? null) ? self::clusterChoice($selectedCluster) : null,
            'selected_namespace' => $selected['cluster_sources'][$clusterId] ?? ($selected['namespace'] ?? ''),
            'sources' => array_map(fn (array $entry): array => $this->sourceView($entry, $filterQuery, $sourceQuery, $observedSources),
                array_slice($sourceRows, 0, self::PAGE_SIZE)),
            'source_filters' => $sourceFilters,
            'source_next' => count($sourceRows) > self::PAGE_SIZE,
            'vault_destinations' => $this->managers->vaultDestinations(),
        ], $csrf);
    }

    #[Route('/api/settings/discovery/clusters', name: 'settings_discovery_clusters', methods: ['GET'])]
    public function clusters(Request $request): JsonResponse
    {
        $page = self::page($request->query, 'page');
        $search = trim($request->query->getString('q'));
        $clusters = $this->connections->settingsPage($search, 'cluster', '', $page);

        return $this->json(['rows' => array_map(self::clusterChoice(...), $clusters['rows']), 'next' => $clusters['next']], headers: self::PRIVATE_RESPONSE);
    }

    private static function clusterChoice(array $entry): array
    {
        return [
            'id' => $entry['id'], 'kind' => 'Kubernetes cluster', 'name' => $entry['name'], 'identity' => $entry['data']['target'],
            'needs_argo_reference' => '' === ($entry['data']['credential'] ?? ''),
        ];
    }

    private static function matchesSource(array $entry, string $kind, string $query): bool
    {
        return in_array($entry['kind'], ['vm', 'cluster'], true) && ('' === $kind || $entry['kind'] === $kind)
            && ('' === $query || mb_stripos($entry['name'], $query) !== false
                || mb_stripos(self::sourceTarget($entry), $query) !== false || stripos($entry['id'], $query) !== false);
    }

    private static function sourceTarget(array $entry): string
    {
        $port = $entry['data']['port'] ?? '';

        return $entry['data']['target'].('vm' === $entry['kind'] && '' !== $port ? ':'.$port : '');
    }

    private function sourceView(array $entry, array $candidateQuery, array $sourceQuery, array $observedSources): array
    {
        $scope = ConnectionDeliveryDiscovery::scope($entry);
        $section = DashboardListContext::DELIVERY_SOURCE_PREFIX.$entry['id'];
        $url = $this->generateUrl('settings_discovery', $candidateQuery + $sourceQuery + ['_fragment' => $section]);
        $state = $this->connections->inventoryJobState($entry);
        $deliveryJob = 'delivery' === ($entry['data']['operation'] ?? null);

        return [
            'id' => $entry['id'], 'name' => $entry['name'], 'kind' => $entry['kind'], 'section' => $section, 'url' => $url,
            'target' => self::sourceTarget($entry),
            'state' => $state, 'delivery_job' => $deliveryJob,
            'result' => $deliveryJob ? ($entry['data']['result'] ?? '') : '',
            'needs_credential' => Connections::needsManagedCredential($entry),
            'worker_kubeconfig' => 'cluster' === $entry['kind'] && 'worker' === ($entry['data']['credential_mode'] ?? null),
            'job_url' => null !== $state ? $this->generateUrl('frontend_dashboard', [
                'view' => 'queue', 'inventory_connection' => $entry['id'], 'from' => $url, '_fragment' => 'inventory-jobs/'.$entry['id'],
            ]) : null,
            'candidates_url' => isset($observedSources[$scope]) || ($deliveryJob && 'complete' === $state)
                ? $this->generateUrl('settings_discovery', $sourceQuery + ['candidate_source' => $scope, '_fragment' => 'discovered-candidates']) : null,
        ];
    }

    private static function candidateView(array $candidate): array
    {
        return [
            'id' => $candidate['id'], 'kind' => $candidate['kind'], 'label' => $candidate['label'],
            'endpoint' => $candidate['endpoint'], 'evidence' => $candidate['evidence'],
            'sources' => $candidate['sources'], 'retained_sources' => $candidate['retained_sources'], 'target' => $candidate['binding']['target'] ?? null,
            'section' => DashboardListContext::DELIVERY_CANDIDATE_PREFIX.$candidate['id'],
        ];
    }

    private function savedConnection(array $candidate, array $filters, array $connections, array $servers, array $registries): array
    {
        $binding = $candidate['binding'];
        if (!$binding) {
            return [];
        }
        $target = $binding['target'];
        $normalizedTarget = match ($candidate['kind']) {
            'jenkins' => JenkinsConnections::normalizeServer($target),
            'harbor', 'registry' => OperatorSettings::normalizeRegistryHost($target),
            default => null,
        };
        $id = $binding['connection_id'] ?? '';
        $connection = $connections[$id] ?? null;
        $from = ['from' => $this->generateUrl('settings_discovery', $filters + ['_fragment' => DashboardListContext::DELIVERY_CANDIDATE_PREFIX.$candidate['id']])];
        $url = match ($candidate['kind']) {
            'jenkins' => isset($servers[$normalizedTarget])
                ? $this->generateUrl('settings_integrations', $from + ['jenkins' => $normalizedTarget, '_fragment' => 'jenkins']) : null,
            'harbor', 'registry' => isset($registries[$normalizedTarget])
                ? $this->generateUrl('settings_integrations', $from + ['registry' => $normalizedTarget, '_fragment' => 'harbor']) : null,
            'argocd' => 'cluster' === ($connection['kind'] ?? null) && !empty($connection['data']['argo_namespace'])
                ? $this->generateUrl('settings_integrations', $from + ['argo_cluster' => $id, '_fragment' => DashboardListContext::ARGO_SECTION]) : null,
            'vm' => 'vm' === ($connection['kind'] ?? null)
                ? $this->generateUrl('settings_connections', $from + ['edit' => $id, '_fragment' => 'connection-vm']) : null,
            'cluster' => 'cluster' === ($connection['kind'] ?? null)
                ? $this->generateUrl('frontend_dashboard', $from + ['view' => 'clusters', 'edit' => $id]) : null,
            default => null,
        };
        $label = match ($candidate['kind']) {
            'argocd' => $connection ? $connection['name'].' / '.($connection['data']['argo_namespace'] ?? '') : $target,
            'vm', 'cluster' => $connection['data']['target'] ?? $target,
            default => $normalizedTarget ?? $target,
        };

        return ['settings_url' => $url, 'saved_label' => $url ? $label : $target];
    }

    private static function candidateFilters(InputBag $input): array
    {
        $query = trim($input->getString('candidate_q'));
        $kind = $input->getString('candidate_kind');
        $source = trim($input->getString('candidate_source'));
        $page = self::page($input, 'candidate_page');

        return ('' !== $query ? ['candidate_q' => $query] : [])
            + (isset(DeliveryDiscovery::TYPES[$kind]) ? ['candidate_kind' => $kind] : [])
            + ('' !== $source ? ['candidate_source' => $source] : [])
            + ($page > 1 ? ['candidate_page' => $page] : []);
    }

    private static function sourceFilters(InputBag $input): array
    {
        $query = trim($input->getString('source_q'));
        $kind = $input->getString('source_kind');
        $page = self::page($input, 'source_page');

        return ('' !== $query ? ['source_q' => $query] : [])
            + (in_array($kind, ['vm', 'cluster'], true) ? ['source_kind' => $kind] : [])
            + ($page > 1 ? ['source_page' => $page] : []);
    }

    private static function page(InputBag $input, string $parameter): int
    {
        return max(1, min(100000, filter_var($input->getString($parameter), FILTER_VALIDATE_INT) ?: 1));
    }

    #[Route('/settings/discovery/queue', name: 'settings_discovery_queue', methods: ['POST'])]
    public function queue(Request $request): Response
    {
        $this->validateForm($request, 'delivery-queue');
        $id = $request->request->getString('connection');
        $filters = self::candidateFilters($request->request) + self::sourceFilters($request->request);
        try {
            $this->connections->run($id, 'delivery');
            $this->addFlash('success', 'Delivery discovery queued.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        $fragment = preg_match('/^(?:[a-f0-9]{32}|[a-f0-9]{64})$/D', $id) ? DashboardListContext::DELIVERY_SOURCE_PREFIX.$id : 'delivery-sources';

        return $this->redirectToRoute('settings_discovery', $filters + ['_fragment' => $fragment], Response::HTTP_SEE_OTHER);
    }

    #[Route('/settings/discovery/cloud', name: 'settings_discovery_cloud', methods: ['POST'])]
    #[Route('/api/settings/discovery/delivery-cloud', name: 'settings_discovery_cloud_api', methods: ['POST'])]
    public function cloud(Request $request, CloudDeliveryDiscovery $cloud): Response
    {
        $json = 'settings_discovery_cloud_api' === $request->attributes->get('_route');
        if ($expired = $this->validateForm($request, 'delivery-cloud', $json)) {
            return $expired;
        }
        $fields = $request->request;
        $sourceQuery = self::sourceFilters($fields);
        $warnings = [];
        $unavailableKinds = [];
        try {
            $provider = $fields->getString('provider');
            $scope = trim($fields->getString('scope'));
            $region = trim($fields->getString('region'));
            $credential = trim($fields->getString('credential'));
            if ('' === $credential && !$fields->getBoolean('use_worker_identity')) {
                throw new \DomainException('Enter a managed credential reference or select the dashboard’s cloud CLI identity.');
            }
            $candidates = $cloud->discover($provider, $scope, $region, $credential, static function (string $warning, array $kinds) use (&$warnings, &$unavailableKinds): void {
                $warnings[] = $warning;
                array_push($unavailableKinds, ...$kinds);
            });
            $label = ['azure' => 'Azure', 'aws' => 'AWS', 'gcp' => 'GCP'][$provider];
            $source = $label.' · '.$scope.('aws' === $provider ? ' / '.$region : '');
            $count = $this->discovery->record($source, $candidates, $unavailableKinds);
        } catch (\DomainException $error) {
            $message = implode(' ', [$error->getMessage(), ...$warnings]);
            if ($json) {
                return $this->json(['error' => $message], Response::HTTP_UNPROCESSABLE_ENTITY, self::PRIVATE_RESPONSE);
            }
            $this->addFlash('error', $message);

            return $this->redirectToRoute('settings_discovery', $sourceQuery + self::candidateFilters($fields) + ['_fragment' => 'cloud-inventories'], Response::HTTP_SEE_OTHER);
        }
        $this->addFlash('success', sprintf('Found %d %s in %s.', $count, 1 === $count ? 'candidate' : 'candidates', $source));
        foreach ($warnings as $warning) {
            $this->addFlash('warning', $warning);
        }
        $redirect = $this->generateUrl('settings_discovery', $sourceQuery + ['candidate_source' => $source, '_fragment' => 'discovered-candidates']);

        return $json ? $this->json(['redirect' => $redirect], headers: self::PRIVATE_RESPONSE)
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    #[Route('/settings/discovery/adopt', name: 'settings_discovery_adopt', methods: ['POST'])]
    #[Route('/api/settings/discovery/delivery-adopt', name: 'settings_discovery_adopt_api', methods: ['POST'])]
    public function adopt(Request $request): Response
    {
        $json = 'settings_discovery_adopt_api' === $request->attributes->get('_route');
        if ($expired = $this->validateForm($request, 'delivery-adopt', $json)) {
            return $expired;
        }
        $fields = $request->request;
        $id = $fields->getString('candidate');
        $filters = self::candidateFilters($fields) + self::sourceFilters($fields);
        try {
            $this->discovery->adopt($id, [
                'endpoint' => $fields->getString('endpoint') ?: $fields->getString('server') ?: $fields->getString('host'),
                'reference' => $fields->getString('reference'),
                'cluster' => $fields->getString('cluster'),
                'namespace' => $fields->getString('namespace'),
            ]);
            $this->addFlash('success', 'Discovered connection saved.');
        } catch (\DomainException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, self::PRIVATE_RESPONSE);
            }
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('settings_discovery', ['adopt' => $id, '_fragment' => 'configure'] + $filters, Response::HTTP_SEE_OTHER);
        }

        $redirect = $this->generateUrl('settings_discovery', $filters + ['_fragment' => DashboardListContext::DELIVERY_CANDIDATE_PREFIX.$id]);

        return $json ? $this->json(['redirect' => $redirect], headers: self::PRIVATE_RESPONSE)
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    private function validateForm(Request $request, string $action, bool $json = false): ?Response
    {
        if (!$this->isCsrfTokenValid('settings-'.$action, $request->request->getString('_token'))) {
            if ($json) {
                return $this->json(['error' => 'Your settings session expired. Reload the page and try again.', 'code' => 'csrf_expired'],
                    Response::HTTP_FORBIDDEN, self::PRIVATE_RESPONSE);
            }
            throw $this->createAccessDeniedException('Invalid form token.');
        }

        return null;
    }
}
