<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\HostCollector;
use App\Discovery\Repository;
use App\Secrets\ConnectionCredentials;
use App\Settings\Connections;

final class BinaryTargets
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Repository $repository,
        private readonly Connections $connections,
        private readonly ConnectionCredentials $credentials,
        private readonly HostCollector $hosts,
        private readonly Changes $changes,
    ) {
    }

    public function save(array $input): void
    {
        $path = trim($input['path'] ?? '');
        if (strlen($path) > 512 || !preg_match('~^/(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*$~D', $path)) {
            throw new \DomainException('Enter an absolute path to the installed executable.');
        }
        $connection = $this->host($input['host'] ?? '');
        $location = [
            'host' => $connection['id'] ?? '', 'target' => $connection['data']['target'] ?? '',
            'port' => $connection['data']['port'] ?? '', 'path' => $path,
        ];
        $source = $this->source($input['repository'] ?? '');
        $profile = ['repository' => $source['id'], 'revision' => trim($input['revision'] ?? '')];
        foreach (['build', 'test', 'output'] as $field) {
            $value = trim($input[$field] ?? '');
            if (strlen($value) > 240 || !preg_match('~^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*$~D', $value)) {
                throw new \DomainException('Enter repository-relative paths for the build script, test script, and output.');
            }
            $profile[$field] = $value;
        }
        $profile['builder'] = trim($input['builder'] ?? '');
        if (!preg_match('~^(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[a-f0-9]{64}$~D', $profile['builder'])) {
            throw new \DomainException('Enter an immutable local builder image ID or registry digest.');
        }
        $this->repository->committedFile($source['data']['path'], $profile['revision'], $profile['build']);
        $this->repository->committedFile($source['data']['path'], $profile['revision'], $profile['test']);
        $profile['digest'] = $this->digest($location);
        $name = basename($path).' · '.($connection['name'] ?? gethostname());
        $hostKey = $connection ? 'ssh/'.$location['target'] : gethostname();
        $hostId = hash('sha256', 'linux/'.$hostKey);

        $this->store->db->transactional(function () use ($location, $profile, $source, $hostKey, $hostId, $name): void {
            $id = $this->inventory->asset('binary', $location['host'].'/'.$location['path'], $name, $location + $profile);
            $this->store->db->delete('asset_links', ['target_id' => $id, 'kind' => 'HOSTS']);
            $this->store->db->delete('asset_links', ['source_id' => $id, 'kind' => 'BUILT_FROM']);
            if (!$this->inventory->get($hostId)) {
                $this->inventory->asset('linux', $hostKey, $location['target'] ?: $hostKey);
            }
            $this->inventory->link($hostId, 'HOSTS', $id, 'Registered executable');
            $this->inventory->link($id, 'BUILT_FROM', $source['id'], 'Operator source link');
        });
    }

    public function queue(string $id, string $candidate): string
    {
        $binary = $this->inventory->get($id);
        if ('binary' !== ($binary['kind'] ?? null)) {
            throw new \DomainException('Choose a registered executable.');
        }
        $profile = $binary['data'];
        $source = $this->source($profile['repository']);
        $candidate = trim($candidate);
        $this->repository->sourcePatch($source['data']['path'], $profile['revision'], $candidate);
        if (!hash_equals($profile['digest'], $this->digest($profile))) {
            throw new \DomainException('The installed executable changed. Confirm its source revision before queuing a new build.');
        }

        return $this->changes->queueBinary($source, $profile['revision'], [
            'binary' => $id, 'candidate' => $candidate, 'profile' => $profile,
        ], $binary['name']);
    }

    public function verify(Change $change): bool
    {
        if ('standalone-binary' !== $change->strategy || 'approved' !== $change->getStatus()) {
            throw new \DomainException('Approve the executable before verifying its installation.');
        }
        $plan = $change->data['plan'];
        $sha = $this->digest($plan['profile']);
        $matches = hash_equals($change->data['binary_sha256'], $sha);

        return $this->store->db->transactional(function () use ($change, $plan, $sha, $matches): bool {
            $this->store->record($change->id, 'check', [
                'label' => 'Installed executable SHA-256', 'passed' => $matches, 'round' => 0, 'log' => $sha,
            ]);
            if (!$matches) {
                return false;
            }
            $change->data['deployed_at'] = gmdate(DATE_ATOM);
            if (!$this->changes->move($change, 'verify_binary_installation', 'The installed executable matches the verified artifact.')) {
                throw new \DomainException('The remediation changed before verification. Refresh and try again.');
            }
            $data = $plan['profile'];
            $this->store->db->update('assets', [
                'data' => Store::json(array_replace($data, ['revision' => $plan['candidate'], 'digest' => $sha])),
                'observed_at' => $change->data['deployed_at'],
            ], ['id' => $plan['binary'], 'data' => Store::json($data)]);

            return true;
        });
    }

    private function digest(array $location): string
    {
        $host = $this->host($location['host']);
        if (!$host) {
            return $this->hosts->executableDigest($location['path']);
        }
        $data = $host['data'];
        if (($data['target'] ?? '') !== $location['target'] || ($data['port'] ?? '') !== $location['port']) {
            throw new \DomainException('The host address changed. Reconfirm the executable and its source on the new address.');
        }

        return $this->credentials->ssh(
            $data['credential'],
            fn (array $options): string => $this->hosts->executableDigest($location['path'], $location['target'], $options),
            $location['port'] ?: null,
        );
    }

    private function host(string $id): ?array
    {
        if ('' === $id) {
            return null;
        }
        $connection = $this->connections->get($id);
        if ('vm' !== ($connection['kind'] ?? null) || empty($connection['data']['credential'])) {
            throw new \DomainException('Choose a Linux host connection with a managed SSH credential.');
        }

        return $connection;
    }

    private function source(string $id): array
    {
        $source = $this->inventory->get($id);
        if ('repository' !== ($source['kind'] ?? null) || isset($source['data']['subdirectory'])
            || ($source['data']['role'] ?? '') === 'infrastructure') {
            throw new \DomainException('Choose a registered application repository root.');
        }

        return $source;
    }
}
