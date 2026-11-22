<?php
declare(strict_types=1);

namespace App\Settings;

use App\Audit\Store;
use Symfony\Component\Messenger\MessageBusInterface;

final class KubernetesChecks
{
    private const PREFIX = 'kube-check:';
    private const LIFETIME = 600;

    public function __construct(private readonly Store $store, private readonly MessageBusInterface $bus)
    {
    }

    public function queue(string $actor, string $action, array $input, ?string $connection = null): string
    {
        $id = bin2hex(random_bytes(16));
        $this->store->db->transactional(function () use ($id, $actor, $action, $input, $connection): void {
            $now = time();
            $prefix = self::PREFIX.'%';
            $expires = $this->store->jsonText('data', 'expires');
            $this->store->db->executeStatement("DELETE FROM operator_settings WHERE id LIKE ? AND CAST($expires AS BIGINT) <= ?", [$prefix, $now]);
            $this->store->db->insert('operator_settings', [
                'id' => self::PREFIX.$id,
                'data' => Store::json([
                    'actor' => $actor, 'action' => $action, 'input' => $input, 'connection' => $connection,
                    'status' => 'queued', 'queued_at' => $now, 'expires' => $now + self::LIFETIME,
                ]),
            ]);
            $this->bus->dispatch(new RunKubernetesCheck($id));
        });

        return $id;
    }

    public function get(string $id): ?array
    {
        $data = $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::PREFIX.$id])['data'] ?? null;

        return $data && $data['expires'] > time() ? $data : null;
    }

    public function update(string $id, array $previous, array $next): bool
    {
        return 1 === $this->store->db->update('operator_settings', ['data' => Store::json($next)], [
            'id' => self::PREFIX.$id, 'data' => Store::json($previous),
        ]);
    }
}
