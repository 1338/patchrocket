<?php
declare(strict_types=1);

namespace App\Controller;

use App\Audit\Store;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\KubernetesChecks;
use Symfony\Component\HttpFoundation\Exception\JsonException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

#[Route('/api/kubernetes', name: 'api_kubernetes_')]
final class KubernetesConnectionsApi
{
    public const CSRF = 'kubernetes-connections';

    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly SecretManagers $managers,
        private readonly KubernetesChecks $checks,
        private readonly CsrfTokenManagerInterface $csrf,
    ) {
    }

    #[Route('/connections', name: 'connections', methods: ['GET'])]
    public function list(Request $request): JsonResponse
    {
        $query = $request->query;
        $page = $query->has('page') ? $this->connections->directoryPage(
            'cluster', $query->getString('q'), $query->getInt('page', 1), $query->getString('edit'),
        ) : null;
        $selected = $page['selected'] ?? null;
        $assets = null === $page ? [
            'hosts' => $this->store->db->fetchAllAssociative("SELECT id, name FROM assets WHERE kind = 'linux' ORDER BY name, id"),
            'repositories' => $this->store->db->fetchAllAssociative("SELECT id, name FROM assets WHERE kind = 'repository' ORDER BY name, id"),
        ] : [
            'next' => $page['next'],
            'selected' => $selected ? $this->describe($selected) : null,
            'hosting_vm' => $this->association($selected['data']['host_asset'] ?? '', 'linux'),
            'associated_repository' => $this->association($selected['data']['repository'] ?? '', 'repository'),
        ];

        return new JsonResponse($assets + [
            'connections' => array_map($this->describe(...), $page['rows'] ?? $this->connections->byKind('cluster')),
            'managers' => $this->managers->vaultDestinations(),
            'csrf' => $this->csrf->getToken(self::CSRF)->getValue(),
            'credentialTestToken' => $this->csrf->getToken('settings-manager-test')->getValue(),
        ]);
    }

    private function association(string $id, string $kind): ?array
    {
        return '' === $id ? null : $this->store->row('SELECT id, kind, name FROM assets WHERE id = ? AND kind = ?', [$id, $kind]);
    }

    #[Route('/contexts', name: 'contexts', methods: ['POST'])]
    #[Route('/namespaces', name: 'namespaces', methods: ['POST'])]
    #[Route('/test', name: 'test', methods: ['POST'])]
    public function queue(Request $request): JsonResponse
    {
        return $this->write($request, function (array $data, string $actor) use ($request): JsonResponse {
            $action = substr($request->attributes->getString('_route'), strlen('api_kubernetes_'));
            if ('namespaces' === $action) {
                $data = array_replace($data, ['namespaceMode' => 'all']);
            }
            $input = $this->selection($data, 'contexts' !== $action);
            if ('namespaces' === $action && '' !== ($query = strtolower($this->field($data, 'namespaceQuery')))) {
                if (!preg_match('/^[a-z0-9-]{1,63}$/D', $query)) {
                    throw new \DomainException('Search with up to 63 letters, numbers or hyphens.');
                }
                $input['namespaceQuery'] = $query;
            }
            $id = $this->checks->queue($actor, $action, $input);

            return new JsonResponse(['statusUrl' => '/api/kubernetes/checks/'.$id], 202);
        });
    }

    #[Route('/checks/{id}', name: 'check', requirements: ['id' => '[a-f0-9]{32}'], methods: ['GET'])]
    public function check(Request $request, string $id): JsonResponse
    {
        $row = $this->checks->get($id);
        if (!$row || $row['actor'] !== $request->attributes->get('_dashboard_actor')) {
            return new JsonResponse(['error' => 'The check expired. Start a new check.'], 404);
        }
        if ('failed' === $row['status']) {
            return new JsonResponse(['error' => $row['result']['error']], 422);
        }
        if ('complete' !== $row['status']) {
            return new JsonResponse(['status' => $row['status'], 'statusUrl' => '/api/kubernetes/checks/'.$id], 202);
        }

        return new JsonResponse($row['result'] + ['checkId' => $id, 'expiresAt' => $row['expires']]);
    }

    #[Route('/credentials', name: 'credentials', methods: ['POST'])]
    public function import(Request $request): JsonResponse
    {
        return $this->write($request, function (array $data): JsonResponse {
            $manager = $this->field($data, 'manager');
            $kubeconfig = $this->field($data, 'kubeconfig');
            if ('' === $kubeconfig || strlen($kubeconfig) > 85000) {
                throw new \DomainException('Choose a kubeconfig file up to 85 KB.');
            }
            try {
                $config = Yaml::parse($kubeconfig, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE, maxNestingLevel: 20);
            } catch (ParseException) {
                throw new \DomainException('The kubeconfig is not valid YAML.');
            }
            if (!is_array($config) || 'Config' !== ($config['kind'] ?? null) || empty($config['contexts']) || !is_array($config['users'] ?? null)) {
                throw new \DomainException('Choose a kubeconfig with at least one context and its inline credentials.');
            }
            foreach ($config['users'] as $entry) {
                $user = is_array($entry) ? ($entry['user'] ?? null) : null;
                if (!is_array($user) || array_diff(array_keys($user), ['token', 'client-certificate-data', 'client-key-data'])
                    || (!isset($user['token']) && !(isset($user['client-certificate-data'], $user['client-key-data'])))) {
                    throw new \DomainException('Import an inline token or certificate pair. Use a worker context for credentials that need an authentication plugin.');
                }
            }

            $reference = $this->managers->storeVaultBundle($manager, Store::json(['kubeconfig' => $kubeconfig]));

            return new JsonResponse(['reference' => $reference], 201);
        });
    }

    #[Route('/connections', name: 'save', methods: ['POST'])]
    public function save(Request $request): JsonResponse
    {
        return $this->write($request, function (array $data, string $actor): JsonResponse {
            $selection = $this->selection($data, true);
            $id = $this->field($data, 'id');
            $previous = '' === $id ? null : $this->connections->get($id);
            if ('' !== $id && 'cluster' !== ($previous['kind'] ?? null)) {
                throw new \DomainException('Choose an existing Kubernetes connection.');
            }
            $old = $previous ? $this->describe($previous) : null;
            $same = $old && $this->selection($old, true) === $selection;
            $check = $this->checks->get($this->field($data, 'checkId'));
            $verified = $check && $check['actor'] === $actor && 'test' === $check['action']
                && $check['input'] === $selection && 'complete' === $check['status']
                && true === ($check['result']['passed'] ?? false);
            if (!$same && !$verified) {
                throw new \DomainException('Run a successful worker test for this context, credential, and namespace scope before saving.');
            }
            $asset = $this->field($data, 'host_asset');
            if ($asset && 'linux' !== $this->store->db->fetchOne('SELECT kind FROM assets WHERE id = ?', [$asset])) {
                throw new \DomainException('Choose a hosting VM from the inventory.');
            }
            $repository = array_key_exists('repository', $data) ? $this->field($data, 'repository') : ($previous['data']['repository'] ?? '');
            if ($repository && 'repository' !== $this->store->db->fetchOne('SELECT kind FROM assets WHERE id = ?', [$repository])) {
                throw new \DomainException('Choose a repository from the inventory.');
            }
            $registries = $data['registries'] ?? '';
            if (is_array($registries) && array_is_list($registries) && count(array_filter($registries, 'is_string')) === count($registries)) {
                $registries = implode(', ', $registries);
            }
            if (!is_string($registries)) {
                throw new \DomainException('Enter registry hosts separated by commas.');
            }

            $settings = [
                'id' => $id, 'name' => $this->field($data, 'name'), 'target' => $selection['target'],
                'credential' => $selection['credential'], 'credential_mode' => $selection['credentialMode'],
                'namespace_mode' => $selection['namespaceMode'], 'namespaces' => $selection['namespaces'],
                'namespace' => $selection['namespaces'][0] ?? 'default',
                'all_namespaces' => 'all' === $selection['namespaceMode'] ? '1' : '',
                'registries' => $registries, 'platform' => $this->field($data, 'platform'),
                'repository' => $repository, 'host_asset' => $asset,
                'interval' => $data['interval'] ?? 0,
            ];
            $saved = $this->store->db->transactional(function () use ($settings, $verified, $check, $previous, $actor): string {
                $saved = $this->connections->save('cluster', $settings);
                if ($verified && ($savedRow = $this->connections->get($saved))) {
                    if (!$this->connections->update($savedRow, array_replace($savedRow['data'], [
                        'last_connection_test' => $check['checked_at'] ?? gmdate(DATE_ATOM),
                        'test_passed' => true,
                        'test_endpoint' => $check['result']['endpoint'] ?? null,
                    ]))) {
                        throw new \DomainException('The connection changed while saving. Reload and try again.');
                    }
                }
                $this->store->record('connections', $previous ? 'kubernetes.connection.updated' : 'kubernetes.connection.created', [
                    'actor' => $actor, 'connection' => $saved,
                ]);

                return $saved;
            });

            return new JsonResponse(['id' => $saved], $previous ? 200 : 201);
        });
    }

    #[Route('/connections/{id}/discover', name: 'discover', requirements: ['id' => '[a-f0-9]{32}'], methods: ['POST'])]
    public function discover(Request $request, string $id): JsonResponse
    {
        return $this->write($request, function () use ($id): JsonResponse {
            if ('cluster' !== ($this->connections->get($id)['kind'] ?? null)) {
                return new JsonResponse(['error' => 'Choose an existing Kubernetes connection.'], 404);
            }
            $this->connections->run($id, 'discover');

            return new JsonResponse(['queued' => true], 202);
        });
    }

    #[Route('/connections/{id}/test', name: 'test_saved', requirements: ['id' => '[a-f0-9]{32}'], methods: ['POST'])]
    public function testSaved(Request $request, string $id): JsonResponse
    {
        return $this->write($request, function (array $data, string $actor) use ($id): JsonResponse {
            $row = $this->connections->get($id);
            if ('cluster' !== ($row['kind'] ?? null)) {
                return new JsonResponse(['error' => 'Choose an existing Kubernetes connection.'], 404);
            }
            $check = $this->checks->queue($actor, 'test', $this->selection($this->describe($row), true), $id);

            return new JsonResponse(['statusUrl' => '/api/kubernetes/checks/'.$check], 202);
        });
    }

    private function describe(array $row): array
    {
        $data = $row['data'];
        return [
            'id' => $row['id'], 'name' => $row['name'], 'target' => $data['target'],
            'credential' => $data['credential'] ?? '', 'credentialMode' => empty($data['credential']) ? 'worker' : 'managed',
            'namespaceMode' => !empty($data['all_namespaces']) ? 'all' : 'selected',
            'namespaces' => !empty($data['all_namespaces']) ? [] : ($data['namespaces'] ?? [($data['namespace'] ?? '') ?: 'default']),
            'interval' => $data['interval'] ?? 0, 'registries' => $data['registries'] ?? '',
            'platform' => $data['platform'] ?? '', 'host_asset' => $data['host_asset'] ?? '',
            'repository' => $data['repository'] ?? '',
            'status' => $data['status'] ?? null, 'result' => $data['result'] ?? null,
            'finished_at' => $data['finished_at'] ?? null,
            'lastDiscovery' => $data['last_discovery_at'] ?? null,
            'lastTest' => $data['last_connection_test'] ?? null,
            'testPassed' => $data['test_passed'] ?? null,
            'endpoint' => $data['test_endpoint'] ?? null,
        ];
    }

    private function selection(array $data, bool $needsTarget): array
    {
        $credentialMode = $this->field($data, 'credentialMode');
        if (!in_array($credentialMode, ['worker', 'managed'], true)) {
            throw new \DomainException('Choose a credential source.');
        }
        $credential = 'managed' === $credentialMode ? $this->field($data, 'credential') : '';
        if ('managed' === $credentialMode && !SecretManagers::validReference($credential)) {
            throw new \DomainException('Enter a managed kubeconfig reference.');
        }
        $target = $this->field($data, 'target');
        if ($needsTarget && ('' === $target || strlen($target) > 253 || preg_match('/[\x00-\x1f\x7f]/', $target))) {
            throw new \DomainException('Choose a valid kubeconfig context.');
        }
        $namespaceMode = $this->field($data, 'namespaceMode') ?: 'selected';
        $namespaces = 'all' === $namespaceMode ? [] : ($data['namespaces'] ?? []);
        if (!in_array($namespaceMode, ['selected', 'all'], true) || !is_array($namespaces) || !array_is_list($namespaces)
            || count($namespaces) > 20 || ($needsTarget && 'selected' === $namespaceMode && !$namespaces)) {
            throw new \DomainException('Choose all namespaces or enter up to 20 namespace names.');
        }
        foreach ($namespaces as $namespace) {
            if (!is_string($namespace) || !preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
                throw new \DomainException('Enter valid Kubernetes namespace names.');
            }
        }
        $namespaces = array_values(array_unique($namespaces));
        sort($namespaces);

        return compact('credentialMode', 'credential', 'target', 'namespaceMode', 'namespaces');
    }

    private function field(array $data, string $field): string
    {
        $value = $data[$field] ?? '';
        if (!is_string($value)) {
            throw new \DomainException('Enter valid text for '.$field.'.');
        }

        return trim($value);
    }

    private function write(Request $request, callable $action): JsonResponse
    {
        if (!$this->csrf->isTokenValid(new \Symfony\Component\Security\Csrf\CsrfToken(self::CSRF, $request->headers->get('X-CSRF-Token', '')))) {
            return new JsonResponse(['error' => 'Your settings session expired. Reload and try again.', 'code' => 'csrf_expired'], 403);
        }
        try {
            return $action('' === $request->getContent() ? [] : $request->toArray(), $request->attributes->getString('_dashboard_actor'));
        } catch (JsonException) {
            return new JsonResponse(['error' => 'Send a JSON object.'], 400);
        } catch (\DomainException $error) {
            return new JsonResponse(['error' => $error->getMessage()], 422);
        }
    }
}
