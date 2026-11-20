<?php
declare(strict_types=1);

namespace App\Asset;

use App\Audit\Store;

final class Inventory
{
    public function __construct(private readonly Store $store)
    {
    }

    public function asset(string $kind, string $key, string $name, array $data = []): string
    {
        $id = hash('sha256', "$kind/$key");
        $existing = $this->get($id);
        $data = array_replace($existing['data'] ?? [], $data);
        $this->store->put('assets', [
            'id' => $id, 'kind' => $kind, 'name' => $name,
            'observed_at' => gmdate(DATE_ATOM), 'data' => Store::json($data),
        ]);

        return $id;
    }

    public function get(string $id): ?array
    {
        return $this->store->row('SELECT * FROM assets WHERE id = ?', [$id]);
    }

    public function link(string $source, string $kind, string $target, string $discovery): void
    {
        $this->store->put('asset_links', [
            'source_id' => $source, 'target_id' => $target, 'kind' => $kind,
            'observed_at' => gmdate(DATE_ATOM), 'discovery' => $discovery,
        ], ['source_id', 'target_id', 'kind']);
    }

    public function associateRepository(string $assetId, string $repositoryId, string $relationship): void
    {
        $kind = match ($relationship) {
            'built-from' => 'BUILT_FROM',
            'source' => 'ASSOCIATED_SOURCE',
            'deployment' => 'DEPLOYED_FROM',
            default => throw new \InvalidArgumentException('Unsupported repository relationship.'),
        };
        $eligible = 'DEPLOYED_FROM' === $kind ? ['image', 'workload', 'container'] : ['image'];
        if (!in_array($this->get($assetId)['kind'] ?? null, $eligible, true)
            || 'repository' !== ($this->get($repositoryId)['kind'] ?? null)) {
            throw new \DomainException('Supply an eligible asset and a registered repository.');
        }
        $this->link($assetId, $kind, $repositoryId, 'Operator association');
    }

    public function links(string $id): array
    {
        return $this->store->rows(
            'SELECT l.*, a.name, a.kind AS asset_kind, a.id FROM asset_links l
             JOIN assets a ON a.id = CASE WHEN l.source_id = ? THEN l.target_id ELSE l.source_id END
             WHERE l.source_id = ? OR l.target_id = ? ORDER BY l.kind, a.name',
            [$id, $id, $id],
        );
    }

    public function findings(string $id, string $source, array $findings): void
    {
        $this->store->db->transactional(function () use ($id, $source, $findings): void {
            $this->store->db->update('findings', ['active' => 0], ['asset_id' => $id, 'source' => $source]);
            foreach ($findings as $finding) {
                $fingerprint = hash('sha256', Store::json([
                    $id, $source, $finding['advisory'], $finding['package'], $finding['target'],
                ]));
                $this->store->put('findings', [
                    'id' => $fingerprint, 'asset_id' => $id, 'source' => $source,
                    'active' => 1, 'last_seen' => gmdate(DATE_ATOM), 'data' => Store::json($finding),
                ]);
            }
        });
    }
}
