<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use Doctrine\DBAL\ArrayParameterType;

final class ApprovalPolicy
{
    public const INDEPENDENT_VERIFICATION_REQUIRED = 'independent_verification_required';
    private const REPOSITORY_PAGE_SIZE = 25;

    public function __construct(private readonly Store $store, private readonly Inventory $inventory)
    {
    }

    public function configure(string $asset, array $strategies, bool $independent): void
    {
        if ('repository' !== ($this->inventory->get($asset)['kind'] ?? null)) {
            throw new \InvalidArgumentException('Choose a registered repository.');
        }
        if (array_diff($strategies, ['composer', 'npm', 'docker-base', 'iac-image', 'standalone-binary'])) {
            throw new \InvalidArgumentException('Choose a supported strategy.');
        }
        $this->store->put('approval_policies', [
            'id' => $asset,
            'data' => Store::json(['strategies' => $strategies, 'independent' => $independent]),
        ]);
    }

    public function repositoryPage(string $search, string $scope, int $page): array
    {
        $filters = ["a.kind = 'repository'"];
        $params = [];
        if ('custom' === $scope) {
            $filters[] = 'p.id IS NOT NULL';
        } elseif ('default' === $scope) {
            $filters[] = 'p.id IS NULL';
        }
        if (preg_match('/^[a-f0-9]{64}$/iD', $search)) {
            $filters[] = 'a.id = ?';
            $params[] = strtolower($search);
        } elseif ('' !== $search) {
            $filters[] = "LOWER(a.name) LIKE LOWER(?) ESCAPE '!'";
            $params[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }
        $where = implode(' AND ', $filters);
        $limit = self::REPOSITORY_PAGE_SIZE + 1;
        $offset = ($page - 1) * self::REPOSITORY_PAGE_SIZE;
        $rows = $this->store->rows("SELECT a.id, a.name, p.data FROM assets a LEFT JOIN approval_policies p ON p.id = a.id
            WHERE $where ORDER BY LOWER(a.name), a.id LIMIT $limit OFFSET $offset", $params);

        return ['rows' => array_slice($rows, 0, self::REPOSITORY_PAGE_SIZE), 'next' => count($rows) > self::REPOSITORY_PAGE_SIZE];
    }

    public function repository(string $id): ?array
    {
        return '' === $id ? null : $this->store->row("SELECT a.id, a.name, p.data FROM assets a
            LEFT JOIN approval_policies p ON p.id = a.id WHERE a.kind = 'repository' AND a.id = ?", [$id]);
    }

    public function check(Change $change): void
    {
        if ($hold = $this->hold($change)) {
            throw new \DomainException($hold['reason']);
        }
    }

    /** @return array{code: string, reason: string}|null */
    public function hold(Change $change): ?array
    {
        $row = $this->store->row('SELECT p.data FROM approval_policies p JOIN changes c ON c.asset_id = p.id WHERE c.id = ?', [$change->id]);
        if (!$row) {
            return null;
        }

        return self::policyHold($row['data'], $change->strategy, $change->data['patch_sha256'] ?? null, fn () => $this->store->row(
            "SELECT data FROM audit WHERE change_id = ? AND kind = 'independent' ORDER BY id DESC LIMIT 1",
            [$change->id],
        )['data'] ?? null);
    }

    /**
     * @param list<string> $ids
     * @return array<string, array{code: string, reason: string}>
     */
    public function pendingHolds(array $ids): array
    {
        if (!$ids) {
            return [];
        }
        $patchHash = $this->store->jsonString('c.data', 'patch_sha256');
        $rows = $this->store->db->iterateAssociative("SELECT c.id, c.strategy, $patchHash AS patch_sha256, p.data AS policy,
            (SELECT a.data FROM audit a WHERE a.change_id = c.id AND a.kind = 'independent' ORDER BY a.id DESC LIMIT 1) AS proof
            FROM changes c JOIN approval_policies p ON p.id = c.asset_id
            WHERE c.status = 'awaiting_approval' AND c.id IN (?)", [$ids], [ArrayParameterType::STRING]);
        $holds = [];
        foreach ($rows as $row) {
            $policy = json_decode($row['policy'], true, flags: JSON_THROW_ON_ERROR);
            $hold = self::policyHold($policy, $row['strategy'], $row['patch_sha256'], static fn () => isset($row['proof'])
                ? json_decode($row['proof'], true, flags: JSON_THROW_ON_ERROR) : null);
            if ($hold) {
                $holds[$row['id']] = $hold;
            }
        }

        return $holds;
    }

    /** @return array{code: string, reason: string}|null */
    private static function policyHold(array $policy, string $strategy, mixed $patchHash, \Closure $readProof): ?array
    {
        if (!in_array($strategy, $policy['strategies'], true)) {
            return ['code' => 'strategy_held', 'reason' => 'This remediation strategy is held by the repository approval policy.'];
        }
        if (!$policy['independent']) {
            return null;
        }

        $proof = $readProof();
        if (!is_string($patchHash) || '' === $patchHash || !($proof['passed'] ?? false)
            || ($proof['patch_sha256'] ?? null) !== $patchHash) {
            return [
                'code' => self::INDEPENDENT_VERIFICATION_REQUIRED,
                'reason' => 'The repository policy requires a passing independent verification of this patch.',
            ];
        }

        return null;
    }
}
