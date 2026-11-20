<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;

final class ApprovalPolicy
{
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

    public function check(Change $change): void
    {
        $row = $this->store->row('SELECT p.data FROM approval_policies p JOIN changes c ON c.asset_id = p.id WHERE c.id = ?', [$change->id]);
        if (!$row) {
            return;
        }
        $policy = $row['data'];
        if (!in_array($change->strategy, $policy['strategies'], true)) {
            throw new \DomainException('This remediation strategy is held by the repository approval policy.');
        }
        if (!$policy['independent']) {
            return;
        }

        $proof = $this->store->row(
            "SELECT data FROM audit WHERE change_id = ? AND kind = 'independent' ORDER BY id DESC LIMIT 1",
            [$change->id],
        );
        if (!($proof['data']['passed'] ?? false) || ($proof['data']['patch_sha256'] ?? null) !== $change->data['patch_sha256']) {
            throw new \DomainException('The repository policy requires a passing independent verification of this patch.');
        }
    }
}
