<?php
declare(strict_types=1);

namespace App\Settings;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\SecretManagers;
use Symfony\Component\Messenger\MessageBusInterface;

final class Connections
{
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

    public function get(string $id): ?array
    {
        return $this->store->row('SELECT * FROM inventory_connections WHERE id = ?', [$id]);
    }

    public function save(string $kind, array $input): string
    {
        $fields = self::FIELDS[$kind] ?? throw new \DomainException('Choose a connection type.');
        $name = trim($input['name'] ?? '');
        $data = [];
        foreach ($fields as $field) {
            $value = trim($input[$field] ?? '');
            if (strlen($value) > 2000 || str_contains($value, "\0")) {
                throw new \DomainException('A connection field is too long or invalid.');
            }
            $data[$field] = $value;
        }
        if ('' === $name || strlen($name) > 120 || ('' === $data['target'] && 'docker' !== $kind)) {
            throw new \DomainException('Supply a name and connection target.');
        }
        $managed = in_array($kind, ['vm', 'cluster'], true) || ('repository' === $kind && str_starts_with($data['target'], 'https://'));
        if ($managed && !SecretManagers::validReference($data['credential'] ?? '')) {
            throw new \DomainException('Enter a managed credential reference in manager:secret format.');
        }
        if ('vm' === $kind && !self::validVmTarget($data['target'])) {
            throw new \DomainException('Enter the explicit SSH user and host, for example scanner@vm.example.');
        }
        if ('vm' === $kind && '' !== $data['port'] && false === filter_var($data['port'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]])) {
            throw new \DomainException('Enter an SSH port between 1 and 65535.');
        }
        $minutes = filter_var($input['interval'] ?? '0', FILTER_VALIDATE_INT);
        if (false === $minutes || ($minutes !== 0 && ($minutes < 5 || $minutes > 43200))) {
            throw new \DomainException('Enter 0 for manual scans, or an interval between 5 minutes and 30 days.');
        }
        if (('docker' === $kind && $minutes) || ('cluster' === $kind && $minutes && !$data['registries'])) {
            throw new \DomainException('Scheduled cluster scans require an explicit registry list. Docker connection schedules use individual image assets.');
        }
        if ('cluster' === $kind) {
            if (array_key_exists('argo_namespace', $input)) {
                $this->validateArgoNamespace($data['argo_namespace']);
            } else {
                unset($data['argo_namespace']);
            }
        }
        if ('repository' === $kind && $data['canonical_url'] && !Repository::identity($data['canonical_url'])) {
            throw new \DomainException('Enter a Git repository URL for matching Argo CD sources.');
        }
        if ('repository' === $kind && $data['canonical_url']) {
            $data['canonical_url'] = Repository::safeUrl($data['canonical_url']);
        }
        $data['interval'] = $minutes;
        $data['next_at'] = $minutes ? time() + $minutes * 60 : 0;
        $id = $input['id'] ?? '';
        if ($id) {
            $existing = $this->get($id);
            if (!$existing || $existing['kind'] !== $kind) {
                throw new \DomainException('This connection does not exist.');
            }
            if ($this->active($existing['data'])) {
                throw new \DomainException('Wait for the inventory job to finish before editing the connection.');
            }
            $data = array_replace($existing['data'], $data);
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

    public function run(string $id, string $action, bool $dueOnly = false): bool
    {
        if (!in_array($action, ['discover', 'scan', 'argo', 'delivery'], true)) {
            throw new \DomainException('Choose an inventory action.');
        }
        return $this->store->db->transactional(function () use ($id, $action, $dueOnly): bool {
            $row = $this->get($id) ?? throw new \DomainException('This connection does not exist.');
            $previous = $row['data'];
            if ('argo' === $action && ('cluster' !== $row['kind'] || empty($previous['argo_namespace']) || '' === self::argoCredential($previous))) {
                throw new \DomainException('Set an Argo CD namespace and managed read credential in Delivery integrations.');
            }
            if ('delivery' === $action && (!in_array($row['kind'], ['vm', 'cluster'], true)
                || !SecretManagers::validReference($previous['credential'] ?? ''))) {
                throw new \DomainException('Choose a host or Kubernetes connection with a managed credential.');
            }
            if ($dueOnly && (empty($previous['interval']) || ($previous['next_at'] ?? PHP_INT_MAX) > time() || $this->active($previous))) {
                return false;
            }
            if ($this->active($previous)) {
                throw new \DomainException('This connection already has a queued or running job.');
            }
            $token = bin2hex(random_bytes(12));
            $data = array_replace($previous, ['token' => $token, 'status' => 'queued', 'queued_at' => time(), 'result' => '']);
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

    private function active(array $data): bool
    {
        return in_array($data['status'] ?? '', ['queued', 'running'], true) && ($data['queued_at'] ?? 0) + 3600 > time();
    }

    public function update(array $row, array $data): bool
    {
        return 1 === $this->store->db->update('inventory_connections', ['data' => Store::json($data)], [
            'id' => $row['id'], 'data' => Store::json($row['data']),
        ]);
    }
}
