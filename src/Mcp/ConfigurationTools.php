<?php
declare(strict_types=1);

namespace App\Mcp;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\KubernetesChecks;
use App\Settings\OperatorSettings;

final class ConfigurationTools
{
    private const ACTOR = 'local-mcp-operator';
    private const KINDS = ['repository', 'cluster', 'registry', 'docker', 'vm'];

    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly KubernetesChecks $checks,
        private readonly OperatorSettings $settings,
        private readonly JenkinsConnections $jenkins,
    ) {
    }

    public function tools(): array
    {
        $id = ['connection_id' => Tool::id('Configured connection ID.', 32)];
        $check = ['check_id' => Tool::id('Worker connection check ID.', 32)];
        $kind = ['kind' => Tool::choice('Inventory connection type.', self::KINDS)];
        $target = ['target' => Tool::text('Repository URL or worker checkout, cluster context, registry image, Docker context target or SSH host.', 1024)];
        $credential = ['credential' => Tool::text('Existing managed credential reference in manager:secret format.', 1057)];
        $access = $target + $credential + [
            'subdirectory' => Tool::text('Optional repository-relative directory.'),
            'credential_mode' => Tool::choice('Kubeconfig source, defaults to managed.', ['managed', 'worker']),
            'namespace_mode' => Tool::choice('Kubernetes namespace scope, defaults to selected.', ['all', 'selected']),
            'namespaces' => Tool::listOf(Tool::text('Kubernetes namespace.', 63), 20),
        ];
        $settings = $access + [
            'name' => Tool::text('Connection display name.', 120),
            'canonical_url' => Tool::text('Canonical repository URL for SCM provenance.'),
            'role' => Tool::choice('Repository role, defaults to application.', ['application', 'infrastructure']),
            'infra_context' => Tool::text('Kubernetes context for infrastructure repository matching.'),
            'editable' => Tool::text('Whitespace-separated editable PHP paths for the configured repository.', 2000),
            'interval' => Tool::integer('Scan interval in minutes. Use 0 for manual scans.', 0, 43200),
            'platform' => Tool::text('Linux image platform.', 64),
            'registries' => Tool::text('Registry hostnames separated by commas for cluster scans.', 2000),
            'repository' => Tool::id('Optional associated source repository asset ID.', 64),
            'host_asset' => Tool::id('Optional hosting Linux VM asset ID.', 64),
            'context' => Tool::text('Docker context name.'),
            'port' => Tool::integer('SSH port.', 1, 65535),
            'docker_inventory' => Tool::boolean('Collect Docker inventory on this SSH target.'),
            'docker_sudo' => Tool::boolean('Use sudo for Docker inventory on this SSH target.'),
            'package_updates' => Tool::boolean('Enable this SSH connection for approved package updates.'),
        ];

        return [
            'connections_list' => Tool::define('List configured repository, registry, Kubernetes, Docker and VM connections and discovery state. Credential references are excluded.', $kind + [
                'limit' => Tool::integer('Maximum rows. Defaults to 20.', 1, 50), 'offset' => Tool::integer('Rows to skip.', 0, 10000),
            ], [], $this->listConnections(...)),
            'connection_test' => Tool::define('Ask the worker to test repository or Kubernetes access and scope before saving a connection.',
                ['kind' => Tool::choice('Connection type to test.', ['repository', 'cluster'])] + $access, ['kind', 'target'],
                $this->test(...), readOnly: false),
            'connection_check' => Tool::define('Read the result of a repository or Kubernetes connection worker check.', $check, ['check_id'],
                fn (array $args): array => $this->check($args['check_id'])),
            'connection_save' => Tool::define('Create or update dashboard-connected SCM, cluster, registry, Docker or VM settings. Repository and cluster access changes require a passing worker check.',
                $kind + $id + $check + ['settings' => Tool::object($settings, ['name', 'target'])], ['kind', 'settings'],
                $this->save(...), readOnly: false, destructive: true),
            'connection_run' => Tool::define('Queue the selected inventory, defensive scan, Argo CD or delivery-discovery operation for a saved connection.', $id + [
                'operation' => Tool::choice('Inventory operation.', ['discover', 'scan', 'argo', 'delivery']),
            ], ['connection_id', 'operation'], fn (array $args): array => [
                'connection_id' => $args['connection_id'],
                'queued' => $this->connections->run($args['connection_id'], $args['operation']),
            ], readOnly: false),
            'delivery_integrations_list' => Tool::define('List configured Jenkins servers and registry hosts without their managed credential references.', [], [],
                fn (): array => [
                    'jenkins_servers' => array_values(array_column($this->jenkins->all(), 'server')),
                    'registry_hosts' => $this->settings->registries(),
                ]),
            'jenkins_configure' => Tool::define('Save a Jenkins connection using an existing managed credential reference.', [
                'server' => Tool::text('Jenkins server base URL including its context path, if present.'),
            ] + $credential, ['server', 'credential'], function (array $args): array {
                $this->jenkins->save($args['server'], $args['credential']);

                return ['saved' => true];
            }, readOnly: false, destructive: true),
            'registry_configure' => Tool::define('Set the managed credential reference used to pull and verify images from a registry.', [
                'host' => Tool::text('Registry hostname with optional port.', 253),
            ] + $credential, ['host', 'credential'], function (array $args): array {
                $this->settings->saveRegistryReference($args['host'], $args['credential']);

                return ['saved' => true];
            }, readOnly: false, destructive: true),
            'argocd_configure' => Tool::define('Configure Argo CD discovery for a saved Kubernetes connection.', $id + $credential + [
                'namespace' => Tool::text('Namespace containing Argo CD Applications.', 63),
            ], ['connection_id', 'namespace'], function (array $args): array {
                $this->connections->saveArgo($args['connection_id'], $args['namespace'], $args['credential'] ?? '');

                return ['saved' => true, 'connection_id' => $args['connection_id']];
            }, readOnly: false, destructive: true),
        ];
    }

    private function listConnections(array $args): array
    {
        $rows = isset($args['kind']) ? $this->connections->byKind($args['kind']) : $this->connections->all();
        $limit = $args['limit'] ?? 20;
        $offset = $args['offset'] ?? 0;

        return [
            'connections' => array_map(self::connection(...), array_slice($rows, $offset, $limit)),
            'has_more' => count($rows) > $offset + $limit,
        ];
    }

    private static function connection(array $row): array
    {
        $data = $row['data'];
        $target = $data['target'] ?? '';
        if ('repository' === $row['kind'] && !str_starts_with($target, '/')) {
            $target = Repository::safeUrl($target);
        }

        return ['connection_id' => $row['id'], 'kind' => $row['kind'], 'name' => $row['name'], 'target' => $target,
            'has_managed_credential' => !empty($data['credential']),
            'canonical_url' => isset($data['canonical_url']) ? Repository::safeUrl($data['canonical_url']) : null,
            'namespaces' => 'cluster' === $row['kind'] ? Connections::clusterNamespaces($data) : null]
            + array_intersect_key($data, array_flip(['role', 'subdirectory', 'infra_context', 'platform', 'argo_namespace', 'interval', 'status', 'operation', 'finished_at']));
    }

    private function test(array $args): array
    {
        $kind = $args['kind'];
        $selection = self::selection($kind, $args);
        $id = $this->checks->queue(self::ACTOR, 'repository' === $kind ? 'repository' : 'test', $selection);

        return ['check_id' => $id, 'status' => 'queued'];
    }

    private function check(string $id): array
    {
        $row = $this->checks->get($id);
        if (!$row || $row['actor'] !== self::ACTOR) {
            throw new \DomainException('The check is unknown or expired. Start a new worker check.');
        }

        return ['check_id' => $id, 'status' => $row['status'], 'expires_at' => $row['expires']]
            + array_intersect_key($row['result'] ?? [], array_flip(['passed', 'revision', 'endpoint', 'error']));
    }

    private function save(array $args): array
    {
        $kind = $args['kind'];
        $fields = (array) $args['settings'];
        $existing = isset($args['connection_id']) ? $this->connections->get($args['connection_id']) : null;
        if (isset($args['connection_id']) && (!$existing || $existing['kind'] !== $kind)) {
            throw new \DomainException('Choose an existing connection of the specified kind.');
        }
        $previous = $existing['data'] ?? [];
        if ('cluster' === $kind && $existing) {
            $previous['namespaces'] = Connections::clusterNamespaces($previous) ?? [];
            $previous['namespace_mode'] = Connections::clusterNamespaces($previous) === null ? 'all' : 'selected';
            $previous['credential_mode'] ??= empty($previous['credential']) ? 'worker' : 'managed';
        }

        $fields += $previous;
        $verified = null;
        if (in_array($kind, ['repository', 'cluster'], true)) {
            $selection = self::selection($kind, $fields);
            $same = $existing && self::selection($kind, $previous) === $selection;
            $verified = $this->checks->get($args['check_id'] ?? '');
            if (!$verified || $verified['actor'] !== self::ACTOR || $verified['action'] !== ('repository' === $kind ? 'repository' : 'test')
                || $verified['input'] !== $selection || 'complete' !== $verified['status'] || true !== ($verified['result']['passed'] ?? false)) {
                $verified = null;
            }
            if (!$same && !$verified) {
                throw new \DomainException('Run a passing worker test before saving changed access settings.');
            }
            if ('cluster' === $kind) {
                $fields = array_replace($fields, [
                    'target' => $selection['target'], 'credential' => $selection['credential'], 'credential_mode' => $selection['credentialMode'],
                    'namespace_mode' => $selection['namespaceMode'], 'namespaces' => $selection['namespaces'],
                ]);
            } else {
                $fields = array_replace($fields, $selection, ['role' => ($fields['role'] ?? '') ?: 'application']);
                if ($existing && !str_starts_with($selection['target'], 'https://')
                    && $selection['target'] === $previous['target']
                    && Repository::safeUrl($fields['canonical_url'] ?? '') === ($previous['canonical_url'] ?? null)) {
                    $fields['credential'] = $previous['credential'] ?? '';
                }
            }
        }
        foreach (['docker_inventory', 'docker_sudo', 'package_updates'] as $key) {
            if (isset($fields[$key]) && is_bool($fields[$key])) {
                $fields[$key] = $fields[$key] ? '1' : '';
            }
        }
        if (isset($fields['port'])) {
            $fields['port'] = (string) $fields['port'];
        }
        foreach (['host_asset' => 'linux', 'repository' => 'repository'] as $field => $assetKind) {
            if (!empty($fields[$field]) && $assetKind !== $this->store->db->fetchOne('SELECT kind FROM assets WHERE id = ?', [$fields[$field]])) {
                throw new \DomainException('Choose an existing inventory asset for '.$field.'.');
            }
        }

        return $this->store->db->transactional(function () use ($kind, $fields, $args, $existing, $verified): array {
            $id = $this->connections->save($kind, ['id' => $args['connection_id'] ?? ''] + $fields, $existing['data'] ?? null);
            $row = $this->connections->get($id) ?? throw new \DomainException('The saved connection is unavailable.');
            if ($verified) {
                $evidence = 'repository' === $kind ? ['last_repository_test' => $verified['checked_at']] : [
                    'last_connection_test' => $verified['checked_at'], 'test_passed' => true,
                    'test_endpoint' => $verified['result']['endpoint'] ?? null,
                ];
                if (!$this->connections->update($row, array_replace($row['data'], $evidence))) {
                    throw new \DomainException('The connection changed while saving. Reload and try again.');
                }
            }
            $this->store->record('connections', $kind.'.connection.'.($existing ? 'updated' : 'created'), ['actor' => self::ACTOR, 'connection' => $id]);

            return self::connection($this->connections->get($id) ?? $row);
        });
    }

    private static function selection(string $kind, array $fields): array
    {
        $target = trim($fields['target'] ?? '');
        $credential = trim($fields['credential'] ?? '');
        if ('repository' === $kind) {
            $subdirectory = trim($fields['subdirectory'] ?? '');
            if ('' !== $subdirectory && !preg_match('#^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)*$#D', $subdirectory)) {
                throw new \DomainException('Enter a repository-relative directory without traversal segments.');
            }
            if (str_starts_with($target, '/')) {
                $credential = '';
            } elseif (!\App\Secrets\ManagedGit::supportsUrl($target) || !SecretManagers::validReference($credential)) {
                throw new \DomainException('Choose an absolute worker checkout or an HTTPS repository URL with a managed credential reference.');
            }

            return compact('target', 'credential', 'subdirectory');
        }

        $credentialMode = $fields['credential_mode'] ?? 'managed';
        $credential = 'managed' === $credentialMode ? $credential : '';
        if ('managed' === $credentialMode && !SecretManagers::validReference($credential)) {
            throw new \DomainException('Enter a managed kubeconfig reference.');
        }
        if ('' === $target || strlen($target) > 253 || preg_match('/[\x00-\x1f\x7f]/', $target)) {
            throw new \DomainException('Choose a valid kubeconfig context.');
        }
        $namespaceMode = $fields['namespace_mode'] ?? 'selected';
        $namespaces = 'all' === $namespaceMode ? [] : array_values(array_unique($fields['namespaces'] ?? []));
        if ('selected' === $namespaceMode && !$namespaces) {
            throw new \DomainException('Choose all namespaces or supply selected Kubernetes namespaces.');
        }
        foreach ($namespaces as $namespace) {
            if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $namespace)) {
                throw new \DomainException('Enter valid Kubernetes namespace names.');
            }
        }
        sort($namespaces);

        return compact('credentialMode', 'credential', 'target', 'namespaceMode', 'namespaces');
    }
}
