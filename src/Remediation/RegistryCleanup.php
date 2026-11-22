<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Secrets\SecretManagers;
use Symfony\Component\Messenger\MessageBusInterface;

final class RegistryCleanup
{
    public const STATUSES = ['awaiting_approval', 'queued', 'running', 'verified', 'failed', 'cancelled'];
    private const REQUEST = 'registry-cleanup-job:';
    private const CONFIG = 'registry-cleanup-config:';
    private const PAGE_SIZE = 25;

    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly MessageBusInterface $bus,
    ) {
    }

    public function configure(string $host, string $provider, string $credential): void
    {
        if (strlen($host) > 259 || !preg_match('/^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?$/D', $host)
            || !in_array($provider, ['harbor', 'oci'], true)
            || !SecretManagers::validReference($credential)) {
            throw new \DomainException('Enter a registry host, supported API, and managed cleanup credential.');
        }
        $this->store->put('operator_settings', ['id' => self::configId($host), 'data' => Store::json(compact('host', 'provider', 'credential'))]);
    }

    public function disconnect(string $host): void
    {
        $this->store->db->delete('operator_settings', ['id' => self::configId($host)]);
    }

    public function configuration(string $host): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::configId($host)])['data'] ?? null;
    }

    private static function configId(string $host): string
    {
        return self::CONFIG.substr(hash('sha256', $host), 0, 32);
    }

    public static function configurationKey(#[\SensitiveParameter] array $settings): string
    {
        return hash('sha256', Store::json($settings));
    }

    public function configurations(): array
    {
        return array_column($this->store->rows('SELECT data FROM operator_settings WHERE id LIKE ? ORDER BY id', [self::CONFIG.'%']), 'data');
    }

    public function jobs(string $search, string $status, int $page): array
    {
        $where = ['id LIKE ?'];
        $parameters = [self::REQUEST.'%'];
        if ('' !== $status) {
            $state = $this->store->jsonText('data', 'status');
            $where[] = "$state = ?";
            $parameters[] = $status;
        }
        if (preg_match('/^[a-f0-9]{32}$/iD', $search)) {
            $where[] = 'id = ?';
            $parameters[] = self::REQUEST.strtolower($search);
        } elseif ('' !== $search) {
            $host = $this->store->jsonText('data', 'host');
            $repository = $this->store->jsonText('data', 'repository');
            $digest = $this->store->jsonText('data', 'digest');
            $where[] = "LOWER($host || '/' || $repository || '@' || $digest) LIKE LOWER(?) ESCAPE '!'";
            $parameters[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }

        $created = $this->store->jsonText('data', 'created_at');
        $filter = implode(' AND ', $where);
        $limit = self::PAGE_SIZE + 1;
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rows = $this->store->rows("SELECT data FROM operator_settings WHERE $filter ORDER BY $created DESC, id LIMIT $limit OFFSET $offset", $parameters);

        return ['rows' => array_column(array_slice($rows, 0, self::PAGE_SIZE), 'data'), 'next' => count($rows) > self::PAGE_SIZE, 'page' => $page];
    }

    public function job(string $id): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::REQUEST.$id])['data'] ?? null;
    }

    public static function requestId(string $host, string $repository, string $digest): string
    {
        return substr(hash('sha256', "$host/$repository@$digest"), 0, 32);
    }

    /** @return array{string, string, string} */
    public function candidate(string $assetId): array
    {
        $asset = $this->inventory->get($assetId);
        if ('image' !== ($asset['kind'] ?? null) || !preg_match(
            '~^([a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?)/([a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*)(?::[A-Za-z0-9_.-]+)?@(sha256:[a-f0-9]{64})$~D',
            $asset['data']['digest'] ?? '', $parts,
        )) {
            throw new \DomainException('Choose a registry image with an exact SHA-256 digest.');
        }
        if ($this->inventory->imageRuntime($asset)['running'] > 0) {
            throw new \DomainException('PatchRocket has observed this digest in a running container.');
        }

        return [$parts[1], $parts[2], $parts[3]];
    }

    public function propose(string $asset, string $actor): string
    {
        [$host, $repository, $digest] = $this->candidate($asset);
        $settings = $this->configuration($host);
        if (!$settings) {
            throw new \DomainException('Configure cleanup for this registry first.');
        }
        $id = self::requestId($host, $repository, $digest);
        $this->store->db->transactional(function () use ($id, $host, $repository, $digest, $asset, $actor, $settings): void {
            $job = compact('id', 'asset', 'host', 'repository', 'digest', 'actor') + [
                'status' => 'awaiting_approval', 'created_at' => gmdate(DATE_ATOM), 'provider' => $settings['provider'], 'configuration' => self::configurationKey($settings),
            ];
            $previous = $this->job($id);
            if ($previous && !in_array($previous['status'], ['failed', 'cancelled'], true)) {
                throw new \DomainException('A cleanup request already exists for this artifact.');
            }
            if ($previous) {
                $this->transition($previous, $job, $actor);
                return;
            }
            $inserted = $this->store->db->executeStatement('INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING', [self::REQUEST.$id, Store::json($job)]);
            if (!$inserted) {
                throw new \DomainException('A cleanup request already exists for this artifact.');
            }
            $this->audit($job, $actor);
        });

        return $id;
    }

    public function approve(string $id, string $digest, string $actor, bool $reviewed): void
    {
        $job = $this->job($id);
        if (!$job || 'awaiting_approval' !== $job['status'] || $job['digest'] !== $digest || !$reviewed) {
            throw new \DomainException('Confirm the exact digest and review rollback, GitOps, other environments, and registry references before approving.');
        }
        $this->candidate($job['asset']);
        $this->store->db->transactional(function () use ($job, $actor): void {
            $this->transition($job, array_replace($job, ['status' => 'queued', 'approved_by' => $actor, 'approved_at' => time()]), $actor);
            $this->bus->dispatch(new RunRegistryCleanup($job['id']));
        });
    }

    public function cancel(string $id, string $actor): void
    {
        $job = $this->job($id);
        if (!$job || !in_array($job['status'], ['awaiting_approval', 'queued'], true)) {
            throw new \DomainException('Only a pending cleanup can be cancelled.');
        }
        $this->transition($job, array_replace($job, ['status' => 'cancelled']), $actor);
    }

    public function transition(array $previous, array $next, string $actor): void
    {
        $this->store->db->transactional(function () use ($previous, $next, $actor): void {
            if (1 !== $this->store->db->update('operator_settings', ['data' => Store::json($next)], [
                'id' => self::REQUEST.$previous['id'], 'data' => Store::json($previous),
            ])) {
                throw new \DomainException('The cleanup request changed. Refresh and try again.');
            }
            $this->audit($next, $actor);
        });
    }

    private function audit(array $job, string $actor): void
    {
        $this->store->record('registry-cleanup', 'registry_cleanup.'.$job['status'], [
            'id' => $job['id'], 'actor' => $actor, 'host' => $job['host'], 'repository' => $job['repository'], 'digest' => $job['digest'],
        ]);
    }
}
