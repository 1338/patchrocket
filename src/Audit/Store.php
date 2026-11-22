<?php
declare(strict_types=1);

namespace App\Audit;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;

final class Store
{
    public function __construct(public readonly Connection $db)
    {
    }

    public function install(): void
    {
        $schema = new Schema();
        $assets = $schema->createTable('assets');
        $assets->addColumn('id', 'string', ['length' => 64]);
        $assets->addColumn('kind', 'string', ['length' => 32]);
        $assets->addColumn('name', 'text');
        $assets->addColumn('observed_at', 'string', ['length' => 32]);
        $assets->addColumn('data', 'text');
        $assets->setPrimaryKey(['id']);

        $edges = $schema->createTable('asset_links');
        foreach (['source_id', 'target_id', 'kind', 'observed_at', 'discovery'] as $field) {
            $edges->addColumn($field, 'string', ['length' => 64]);
        }
        $edges->setPrimaryKey(['source_id', 'target_id', 'kind']);

        $findings = $schema->createTable('findings');
        foreach (['id', 'asset_id', 'source', 'last_seen'] as $field) {
            $findings->addColumn($field, 'string', ['length' => 64]);
        }
        $findings->addColumn('active', 'integer');
        $findings->addColumn('data', 'text');
        $findings->setPrimaryKey(['id']);
        $findings->addIndex(['asset_id', 'source', 'active']);

        $changes = $schema->createTable('changes');
        foreach (['id', 'asset_id', 'finding_id', 'status', 'created_at', 'strategy'] as $field) {
            $changes->addColumn($field, 'string', ['length' => 64]);
        }
        $changes->addColumn('data', 'text');
        $changes->setPrimaryKey(['id']);
        $changes->addIndex(['finding_id', 'created_at']);

        $audit = $schema->createTable('audit');
        foreach (['id', 'change_id', 'created_at', 'kind'] as $field) {
            $audit->addColumn($field, 'string', ['length' => 64]);
        }
        $audit->addColumn('data', 'text');
        $audit->setPrimaryKey(['id']);
        $audit->addIndex(['change_id', 'id']);

        $schedules = $schema->createTable('scan_schedules');
        $schedules->addColumn('id', 'string', ['length' => 64]);
        $schedules->addColumn('next_at', 'integer');
        $schedules->addColumn('lease_until', 'integer');
        $schedules->addColumn('interval_seconds', 'integer');
        $schedules->addColumn('data', 'text');
        $schedules->setPrimaryKey(['id']);
        $schedules->addIndex(['next_at', 'lease_until']);

        $policies = $schema->createTable('approval_policies');
        $policies->addColumn('id', 'string', ['length' => 64]);
        $policies->addColumn('data', 'text');
        $policies->setPrimaryKey(['id']);

        $releases = $schema->createTable('rollout_schedules');
        $releases->addColumn('id', 'string', ['length' => 64]);
        $releases->addColumn('not_before', 'integer');
        $releases->addColumn('lease_until', 'integer');
        $releases->addColumn('status', 'string', ['length' => 20]);
        $releases->addColumn('data', 'text');
        $releases->setPrimaryKey(['id']);
        $releases->addIndex(['status', 'not_before']);

        $tracking = $schema->createTable('release_tracking');
        $tracking->addColumn('id', 'string', ['length' => 64]);
        $tracking->addColumn('next_at', 'integer');
        $tracking->addColumn('lease_until', 'integer');
        $tracking->addColumn('data', 'text');
        $tracking->setPrimaryKey(['id']);
        $tracking->addIndex(['next_at', 'lease_until']);

        $settings = $schema->createTable('operator_settings');
        $settings->addColumn('id', 'string', ['length' => 64]);
        $settings->addColumn('data', 'text');
        $settings->setPrimaryKey(['id']);

        $connections = $schema->createTable('inventory_connections');
        $connections->addColumn('id', 'string', ['length' => 64]);
        $connections->addColumn('kind', 'string', ['length' => 32]);
        $connections->addColumn('name', 'text');
        $connections->addColumn('data', 'text');
        $connections->setPrimaryKey(['id']);

        $authAttempts = $schema->createTable('dashboard_auth_attempts');
        $authAttempts->addColumn('id', 'string', ['length' => 64]);
        $authAttempts->addColumn('attempts', 'integer');
        $authAttempts->addColumn('expires_at', 'integer');
        $authAttempts->setPrimaryKey(['id']);
        $authAttempts->addIndex(['expires_at']);

        $manager = $this->db->createSchemaManager();
        $newInstallation = !$manager->tablesExist(['operator_settings']);
        if ($this->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform) {
            $this->db->executeStatement('PRAGMA journal_mode = WAL');
        }
        foreach ($schema->getTables() as $table) {
            if (!$manager->tablesExist([$table->getName()])) {
                $manager->createTable($table);
            }
        }
        if ($newInstallation) {
            $this->db->executeStatement(
                'INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING',
                ['auth:bootstrap', self::json(['initialized' => false, 'expires' => 0])],
            );
        }
    }

    public function put(string $table, array $values, array $keys = ['id']): void
    {
        $columns = array_keys($values);
        $updates = array_diff($columns, $keys);
        $conflict = implode(', ', $keys);
        $set = implode(', ', array_map(static fn (string $column): string => "$column = excluded.$column", $updates));
        $this->db->executeStatement(
            sprintf(
                'INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s',
                $table,
                implode(', ', $columns),
                implode(', ', array_fill(0, count($values), '?')),
                $conflict,
                $set,
            ),
            array_values($values),
        );
    }

    public function row(string $sql, array $params = []): ?array
    {
        $row = $this->db->fetchAssociative($sql, $params);

        return false === $row ? null : self::decode($row);
    }

    public function rows(string $sql, array $params = []): array
    {
        return array_map(self::decode(...), $this->db->fetchAllAssociative($sql, $params));
    }

    public function iterate(string $sql, array $params = []): iterable
    {
        foreach ($this->db->iterateAssociative($sql, $params) as $row) {
            yield self::decode($row);
        }
    }

    public function record(string $change, string $kind, array $data): void
    {
        $this->db->insert('audit', [
            'id' => sprintf('%020.0f-%s', microtime(true) * 1000000, bin2hex(random_bytes(6))),
            'change_id' => $change,
            'kind' => $kind,
            'created_at' => gmdate(DATE_ATOM),
            'data' => self::json($data),
        ]);
    }

    public static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
    }

    public function jsonText(string $column, string $key): string
    {
        return $this->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
            ? "CAST(json_extract($column, '$.$key') AS TEXT)"
            : "(CAST($column AS jsonb)->>'$key')";
    }

    public function jsonString(string $column, string $key): string
    {
        $isString = $this->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
            ? "json_type($column, '$.$key') = 'text'"
            : "jsonb_typeof(CAST($column AS jsonb)->'$key') = 'string'";

        return "CASE WHEN $isString THEN ".$this->jsonText($column, $key).' END';
    }

    private static function decode(array $row): array
    {
        if (isset($row['data'])) {
            $row['data'] = json_decode($row['data'], true, flags: JSON_THROW_ON_ERROR);
        }

        return $row;
    }
}
