<?php
declare(strict_types=1);

namespace App\Settings;

use App\Audit\Store;
use App\Remediation\JenkinsBuildStatus;
use App\Secrets\SecretManagers;

final class JenkinsConnections
{
    public function __construct(private readonly Store $store)
    {
    }

    public function all(): array
    {
        return array_column($this->store->rows("SELECT id, data FROM operator_settings WHERE id LIKE 'jenkins:%'"), 'data');
    }

    public function save(string $server, string $reference): void
    {
        $server = rtrim(trim($server), '/');
        $reference = trim($reference);
        if (strlen($server) > 512 || !JenkinsBuildStatus::validServer($server)) {
            throw new \DomainException('Enter the Jenkins base URL, including its context path if it has one.');
        }
        if (!SecretManagers::validReference($reference)) {
            throw new \DomainException('Enter a Jenkins credential reference in manager:secret format.');
        }
        $this->store->put('operator_settings', [
            'id' => $this->id($server), 'data' => Store::json(['server' => $server, 'reference' => $reference]),
        ]);
    }

    public function remove(string $server): void
    {
        $this->store->db->delete('operator_settings', ['id' => $this->id(rtrim(trim($server), '/'))]);
    }

    public function referenceFor(string $job): ?string
    {
        $matches = array_filter($this->all(), static fn (array $entry): bool => JenkinsBuildStatus::serverContainsJob($entry['server'], $job));
        usort($matches, static fn (array $a, array $b): int => strlen($b['server']) <=> strlen($a['server']));

        return $matches[0]['reference'] ?? null;
    }

    private function id(string $server): string
    {
        return 'jenkins:'.substr(hash('sha256', $server), 0, 56);
    }
}
