<?php
declare(strict_types=1);

namespace App\Asset;

use App\Audit\Store;

final class Inventory
{
    private const REPOSITORY_RELATIONSHIPS = [
        'source' => ['kind' => 'ASSOCIATED_SOURCE', 'assets' => ['image']],
        'built-from' => ['kind' => 'BUILT_FROM', 'assets' => ['image']],
        'deployment' => ['kind' => 'DEPLOYED_FROM', 'assets' => ['image', 'workload', 'container']],
    ];

    public function __construct(private readonly Store $store)
    {
    }

    public function asset(string $kind, string $key, string $name, array $data = []): string
    {
        $id = self::assetId($kind, $key);
        $existing = $this->get($id);
        $data = array_replace($existing['data'] ?? [], $data);
        $this->store->put('assets', [
            'id' => $id, 'kind' => $kind, 'name' => $name,
            'observed_at' => gmdate(DATE_ATOM), 'data' => Store::json($data),
        ]);

        return $id;
    }

    public static function assetId(string $kind, string $key): string
    {
        return hash('sha256', "$kind/$key");
    }

    public static function scopeSql(): string
    {
        return "WITH RECURSIVE scope(id) AS (
            SELECT id FROM assets WHERE id = ?
            UNION
            SELECT l.target_id FROM asset_links l JOIN scope s ON l.source_id = s.id
            WHERE l.kind IN ('HOSTS', 'RUNS')
        )";
    }

    public static function isRegistryDigest(mixed $value): bool
    {
        return is_string($value) && 1 === preg_match('~^[a-z0-9\[][a-z0-9._:/\[\]-]*@sha256:[a-f0-9]{64}$~iD', $value);
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
        $definition = self::REPOSITORY_RELATIONSHIPS[$relationship] ?? throw new \InvalidArgumentException('Unsupported repository relationship.');
        if (!in_array($this->get($assetId)['kind'] ?? null, $definition['assets'], true)
            || 'repository' !== ($this->get($repositoryId)['kind'] ?? null)) {
            throw new \DomainException('Supply an eligible asset and a registered repository.');
        }
        $this->link($assetId, $definition['kind'], $repositoryId, 'Operator association');
    }

    public static function repositoryLinkAssetKinds(string $relationship): array
    {
        return self::REPOSITORY_RELATIONSHIPS[$relationship]['assets'] ?? [];
    }

    public static function linkFingerprint(string $source, string $kind, string $target): string
    {
        return hash('sha256', Store::json([$source, $kind, $target]));
    }

    public function repositoryLinkFingerprint(string $asset, string $repository, string $relationship): ?string
    {
        $kind = self::REPOSITORY_RELATIONSHIPS[$relationship]['kind'] ?? null;
        if (null === $kind || !$this->store->db->fetchOne('SELECT 1 FROM asset_links WHERE source_id = ? AND kind = ? AND target_id = ?',
            [$asset, $kind, $repository])) {
            return null;
        }

        return self::linkFingerprint($asset, $kind, $repository);
    }

    public function runtimeFindingAssetIds(bool $running): string
    {
        $digest = $this->store->jsonText('image.data', 'digest');
        $origin = $this->store->jsonText('image.data', 'origin');
        $observations = self::imageRuntimeObservationsSql($this->store);
        $runningOnly = $running ? ' WHERE running = 1' : '';
        $match = "(image.id IN (SELECT image_id FROM observed)
            OR COALESCE($digest IN (SELECT digest FROM observed WHERE digest IS NOT NULL), FALSE))";
        $filter = $running ? $match : "$origin = 'registry' AND NOT $match";

        return "WITH observed AS (
            SELECT DISTINCT image_id, digest FROM ($observations) observations$runningOnly
        ) SELECT image.id FROM assets image WHERE image.kind = 'image' AND $filter";
    }

    public static function imageRuntimeObservationsSql(Store $store): string
    {
        $digest = $store->jsonText('image.data', 'digest');
        $running = $store->jsonText('container.data', 'running');

        return "SELECT container.id, container.name, image.id AS image_id, $digest AS digest,
                CASE WHEN $running IN ('1', 'true') THEN 1 ELSE 0 END AS running
            FROM asset_links link JOIN assets image ON image.id = link.target_id JOIN assets container ON container.id = link.source_id
            WHERE link.kind = 'RUNS' AND image.kind = 'image' AND container.kind = 'container'";
    }

    public function imageRuntime(array $asset): array
    {
        $observationsSql = self::imageRuntimeObservationsSql($this->store);
        $observations = $this->store->db->fetchAssociative(
            "SELECT COUNT(DISTINCT id) AS observed,
                COUNT(DISTINCT CASE WHEN running = 1 THEN id END) AS running FROM ($observationsSql) observations
             WHERE image_id = ? OR digest = ?",
            [$asset['id'], $asset['data']['digest'] ?? null],
        );

        return ['observed' => (int) $observations['observed'], 'running' => (int) $observations['running']];
    }

    public function links(string $id): array
    {
        return $this->store->rows(
            'SELECT l.*, a.name, a.kind AS asset_kind, a.id FROM asset_links l
             JOIN assets a ON a.id = CASE WHEN l.source_id = ? THEN l.target_id ELSE l.source_id END
             WHERE l.source_id = ? OR l.target_id = ? ORDER BY l.kind, a.name, a.id, l.source_id',
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
