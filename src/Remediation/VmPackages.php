<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Settings\Connections;
use Symfony\Component\Messenger\MessageBusInterface;

final class VmPackages
{
    private const SETTINGS_PREFIX = 'vm-package:';
    private const AUDIT_PATTERN = 'vm!_package.%';
    private const ACTIVE = ['plan_queued', 'planning', 'awaiting_approval', 'apply_queued', 'applying', 'verify_queued', 'verifying', 'unverified'];
    private const REVIEW_SECONDS = 3600;
    private const QUEUE_PAGE_SIZE = 50;
    private const HISTORY_PAGE_SIZE = 50;

    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly MessageBusInterface $bus,
    ) {
    }

    public static function supports(array $asset): bool
    {
        $data = $asset['data'];
        return 'linux' === $asset['kind'] && 'APT' === ($data['manager'] ?? null)
            && in_array($data['distribution'] ?? null, ['ubuntu', 'debian'], true);
    }

    public static function findingPackage(array $asset, array $finding): ?string
    {
        $package = $finding['data']['package'] ?? null;
        if (self::supports($asset) && !empty($asset['data']['ssh_alias']) && !empty($finding['active'])
            && $finding['asset_id'] === $asset['id'] && !empty($finding['data']['fixed'])
            && ($finding['data']['type'] ?? null) === $asset['data']['distribution']
            && is_string($package) && self::validPackage($package)) {
            return $package;
        }

        return null;
    }

    public function connection(array $asset): ?array
    {
        $target = $asset['data']['ssh_alias'] ?? '';
        if (!self::supports($asset) || '' === $target || Inventory::assetId('linux', 'ssh/'.$target) !== $asset['id']) {
            return null;
        }

        $targetField = $this->store->jsonText('data', 'target');
        $matches = $this->store->rows("SELECT * FROM inventory_connections WHERE kind = 'vm' AND $targetField = ?", [$target]);
        return 1 === count($matches) ? $matches[0] : null;
    }

    public static function ready(string $asset, ?array $connection): bool
    {
        return $connection && Connections::validVmTarget($connection['data']['target'])
            && !Connections::needsManagedCredential($connection)
            && 'complete' === ($connection['data']['last_discovery']['status'] ?? null)
            && $asset === ($connection['data']['last_discovery']['asset_id'] ?? null);
    }

    private static function key(string $asset): string
    {
        return self::SETTINGS_PREFIX.substr($asset, 0, 48);
    }

    public function job(string $asset): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::key($asset)])['data'] ?? null;
    }

    public function queue(string $state, int $page, int $now, string $asset = ''): array
    {
        $filters = [
            'open' => [...self::ACTIVE, 'failed'],
            'approval' => ['awaiting_approval'],
            'verification' => ['unverified'],
            'worker' => array_values(array_diff(self::ACTIVE, ['awaiting_approval', 'unverified'])),
            'closed' => ['verified', 'closed_unverified', 'cancelled'],
            'all' => [],
        ];
        $state = array_key_exists($state, $filters) ? $state : 'open';
        $asset = preg_match('/^[a-f0-9]{64}$/D', $asset) ? $asset : '';
        $page = '' === $asset ? max(1, min(100000, $page)) : 1;
        $limit = self::QUEUE_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::QUEUE_PAGE_SIZE;
        $status = $this->store->jsonText('j.data', 'status');
        $where = 'j.id LIKE ?';
        $params = [self::SETTINGS_PREFIX.'%'];
        if ('' !== $asset) {
            $where = 'j.id = ?';
            $params = [self::key($asset)];
        } elseif ($filters[$state]) {
            $where .= " AND $status IN (".implode(', ', array_fill(0, count($filters[$state]), '?')).')';
            array_push($params, ...$filters[$state]);
        }
        $jobAsset = $this->store->jsonText('j.data', 'asset');
        $target = $this->store->jsonText('j.data', 'target');
        $package = $this->store->jsonText('j.data', 'package');
        $updated = $this->store->jsonText('j.data', 'updated_at');
        $expires = $this->store->jsonText('j.data', 'expires_at');
        $result = $this->store->jsonText('j.data', 'result');
        $rows = $this->store->db->fetchAllAssociative(
            "SELECT a.id AS asset_id, a.name, $target AS target, $package AS package, $status AS status,
                $result AS result, CAST($updated AS BIGINT) AS updated_at, CAST($expires AS BIGINT) AS expires_at
            FROM operator_settings j JOIN assets a ON a.id = $jobAsset AND a.kind = 'linux'
            WHERE $where
            ORDER BY CASE $status WHEN 'unverified' THEN 0 WHEN 'awaiting_approval' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,
                CAST($updated AS BIGINT) DESC NULLS LAST, a.id
            LIMIT $limit OFFSET $offset", $params,
        );
        $next = count($rows) > self::QUEUE_PAGE_SIZE;
        $rows = array_map(static fn (array $row): array => $row + [
            'approval_expired' => 'awaiting_approval' === $row['status'] && (int) $row['expires_at'] <= $now,
        ], array_slice($rows, 0, self::QUEUE_PAGE_SIZE));

        return compact('rows', 'state', 'page', 'next', 'asset');
    }

    public function history(string $asset, int $page): array
    {
        $page = max(1, min(100000, $page));
        $limit = self::HISTORY_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::HISTORY_PAGE_SIZE;
        $attemptAsset = $this->store->jsonText('data', 'asset');
        $snapshotAsset = $this->store->jsonText('snapshot.data', 'asset');
        $rows = $this->store->rows(
            "SELECT started.change_id, started.created_at AS started_at, latest.created_at, latest.data
             FROM (
                 SELECT id, change_id, created_at FROM audit
                 WHERE kind = 'vm_package.plan_queued' AND $attemptAsset = ?
                 ORDER BY id DESC LIMIT $limit OFFSET $offset
             ) started JOIN audit latest ON latest.id = (
                 SELECT snapshot.id FROM audit snapshot WHERE snapshot.change_id = started.change_id
                     AND snapshot.kind LIKE ? ESCAPE '!' AND $snapshotAsset = ?
                 ORDER BY snapshot.id DESC LIMIT 1
             ) ORDER BY started.id DESC", [$asset, self::AUDIT_PATTERN, $asset],
        );

        return ['rows' => array_slice($rows, 0, self::HISTORY_PAGE_SIZE), 'page' => $page, 'next' => count($rows) > self::HISTORY_PAGE_SIZE];
    }

    public function historyPageForAttempt(string $asset, string $attempt): ?int
    {
        $startedAsset = $this->store->jsonText('started.data', 'asset');
        $newerAsset = $this->store->jsonText('newer.data', 'asset');
        $preceding = $this->store->db->fetchOne(
            "SELECT (SELECT COUNT(*) FROM audit newer WHERE newer.kind = 'vm_package.plan_queued' AND $newerAsset = ? AND newer.id > started.id)
             FROM audit started WHERE started.change_id = ? AND started.kind = 'vm_package.plan_queued' AND $startedAsset = ?
             ORDER BY started.id DESC LIMIT 1", [$asset, $attempt, $asset],
        );

        return false === $preceding ? null : intdiv((int) $preceding, self::HISTORY_PAGE_SIZE) + 1;
    }

    public function historyAttempt(string $asset, string $attempt, int $page): ?array
    {
        $page = max(1, min(100000, $page));
        $limit = self::HISTORY_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::HISTORY_PAGE_SIZE;
        $assetField = $this->store->jsonText('data', 'asset');
        $condition = "FROM audit WHERE change_id = ? AND kind LIKE ? ESCAPE '!' AND $assetField = ?";
        $parameters = [$attempt, self::AUDIT_PATTERN, $asset];
        $latest = $this->store->row("SELECT id, data $condition ORDER BY id DESC LIMIT 1", $parameters);
        if (!$latest) {
            return null;
        }
        $events = $this->store->rows("SELECT id, created_at, data $condition AND id <= ? ORDER BY id LIMIT $limit OFFSET $offset",
            [...$parameters, $latest['id']]);

        return ['job' => $latest['data'], 'events' => array_slice($events, 0, self::HISTORY_PAGE_SIZE),
            'page' => $page, 'next' => count($events) > self::HISTORY_PAGE_SIZE];
    }

    public function prepare(string $asset, string $package, string $actor): void
    {
        if (!self::validPackage($package)) {
            throw new RemediationFieldError('package', 'Enter one APT package name, optionally with its architecture.');
        }
        $connection = $this->enabledConnection($asset);
        $old = $this->job($asset);
        if ($old && in_array($old['status'], self::ACTIVE, true)) {
            throw new \DomainException('Resolve or cancel the current package update before preparing another.');
        }

        $this->store->db->transactional(function () use ($asset, $package, $actor, $connection, $old): void {
            $job = [
                'id' => bin2hex(random_bytes(16)), 'asset' => $asset, 'package' => $package,
                'target' => $connection['data']['target'], 'connection' => self::connectionKey($connection),
                'status' => 'plan_queued', 'requested_by' => $actor, 'updated_at' => time(),
            ];
            if ($old) {
                $this->transition($old, $job, $actor);
            } else {
                if (!$this->store->db->executeStatement(
                    'INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING',
                    [self::key($asset), Store::json($job)],
                )) {
                    throw new \DomainException('A package update already exists for this asset.');
                }
                $this->audit($job, $actor);
            }
            $this->bus->dispatch(new RunVmPackage($asset, $job['id'], 'plan'));
        });
    }

    private static function validPackage(string $package): bool
    {
        return (bool) preg_match('/^[a-z0-9][a-z0-9+.-]{1,127}(?::[a-z0-9][a-z0-9-]{0,31})?$/D', $package);
    }

    public function approve(string $asset, string $id, string $version, bool $reviewed, string $actor): void
    {
        $job = $this->current($asset, $id, ['awaiting_approval']);
        if (time() >= $job['expires_at']) {
            throw new \DomainException('The package plan expired. Cancel it and prepare a new plan.');
        }
        if ($version !== $job['plan']['version']) {
            throw new RemediationFieldError('version', 'Enter the exact target version shown in the plan.');
        }
        if (!$reviewed) {
            throw new RemediationFieldError('reviewed', 'Confirm that you reviewed the change, maintenance window and recovery plan.');
        }
        $this->jobConnection($job);
        $this->enqueue($job, 'apply', $actor, ['approved_by' => $actor, 'approved_at' => time()]);
    }

    public function verify(string $asset, string $id, string $actor): void
    {
        $job = $this->current($asset, $id, ['unverified']);
        $this->jobConnection($job);
        $this->enqueue($job, 'verify', $actor);
    }

    public function cancel(string $asset, string $id, string $actor): void
    {
        $job = $this->current($asset, $id, ['plan_queued', 'awaiting_approval', 'apply_queued', 'unverified']);
        $status = 'unverified' === $job['status'] ? 'closed_unverified' : 'cancelled';
        $this->transition($job, array_replace($job, ['status' => $status, 'updated_at' => time()]), $actor);
    }

    public function jobConnection(array $job): array
    {
        $connection = $this->enabledConnection($job['asset']);
        if (!hash_equals($job['connection'], self::connectionKey($connection))) {
            throw new \DomainException('The VM package connection changed. Review its settings and prepare a new plan.');
        }

        return $connection['data'];
    }

    public function transition(array $old, array $next, string $actor): void
    {
        $this->store->db->transactional(function () use ($old, $next, $actor): void {
            if (1 !== $this->store->db->update('operator_settings', ['data' => Store::json($next)], [
                'id' => self::key($old['asset']), 'data' => Store::json($old),
            ])) {
                throw new \DomainException('The package update state changed. Refresh and try again.');
            }
            $this->audit($next, $actor);
        });
    }

    public function reviewDeadline(): int
    {
        return time() + self::REVIEW_SECONDS;
    }

    private function enabledConnection(string $asset): array
    {
        $row = $this->inventory->get($asset);
        $connection = $row ? $this->connection($row) : null;
        if (!self::ready($asset, $connection) || '1' !== ($connection['data']['package_updates'] ?? '')) {
            throw new \DomainException('Enable package updates on the managed VM connection in Settings and discover the host.');
        }

        return $connection;
    }

    private static function connectionKey(array $connection): string
    {
        $data = $connection['data'];

        return hash('sha256', Store::json([$connection['id'], $data['target'], $data['port'] ?? '', $data['credential']]));
    }

    private function current(string $asset, string $id, array $states): array
    {
        $job = $this->job($asset);
        if (!$job || $id !== $job['id'] || !in_array($job['status'], $states, true)) {
            throw new \DomainException('This package update is no longer available for that action.');
        }

        return $job;
    }

    private function enqueue(array $job, string $operation, string $actor, array $extra = []): void
    {
        $this->store->db->transactional(function () use ($job, $operation, $actor, $extra): void {
            $this->transition($job, array_replace($job, $extra, [
                'status' => $operation.'_queued', 'updated_at' => time(),
            ]), $actor);
            $this->bus->dispatch(new RunVmPackage($job['asset'], $job['id'], $operation));
        });
    }

    private function audit(array $job, string $actor): void
    {
        $this->store->record($job['id'], 'vm_package.'.$job['status'], ['actor' => $actor] + $job);
    }
}
