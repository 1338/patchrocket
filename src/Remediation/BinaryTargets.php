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

    public function save(array $input): string
    {
        $path = trim($input['path'] ?? '');
        if (strlen($path) > 512 || !preg_match('~^/(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*$~D', $path)) {
            throw new RemediationFieldError('path', 'Enter an absolute path to the installed executable.');
        }
        $connection = $this->host($input['host'] ?? '');
        $location = [
            'host' => $connection['id'] ?? '', 'target' => $connection['data']['target'] ?? '',
            'port' => $connection['data']['port'] ?? '', 'path' => $path,
        ];
        $source = $this->source($input['repository'] ?? '');
        $profile = ['repository' => $source['id'], 'revision' => trim($input['revision'] ?? '')];
        if (!preg_match('/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/D', $profile['revision'])) {
            throw new RemediationFieldError('revision', 'Enter the full Git commit ID for the installed executable.');
        }
        foreach (['build', 'test', 'output'] as $field) {
            $value = trim($input[$field] ?? '');
            if (strlen($value) > 240 || !preg_match('~^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*$~D', $value)) {
                throw new RemediationFieldError($field, 'Enter repository-relative paths for the build script, test script, and output.');
            }
            $profile[$field] = $value;
        }
        $profile['builder'] = trim($input['builder'] ?? '');
        if (!preg_match('~^(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[a-f0-9]{64}$~D', $profile['builder'])) {
            throw new RemediationFieldError('builder', 'Enter an immutable local builder image ID or registry digest.');
        }
        foreach (['build', 'test'] as $field) {
            try {
                $this->repository->committedFile($source['data']['path'], $profile['revision'], $profile[$field]);
            } catch (\DomainException) {
                throw new RemediationFieldError($field, sprintf('Choose a committed %s script available in the installed source commit.', $field));
            }
        }
        $profile['digest'] = $this->digest($location);
        $name = basename($path).' · '.($connection['name'] ?? gethostname());
        $hostKey = $connection ? 'ssh/'.$location['target'] : gethostname();
        $hostId = hash('sha256', 'linux/'.$hostKey);

        return $this->store->db->transactional(function () use ($location, $profile, $source, $hostKey, $hostId, $name): string {
            $id = $this->inventory->asset('binary', $location['host'].'/'.$location['path'], $name, $location + $profile);
            $this->store->db->delete('asset_links', ['target_id' => $id, 'kind' => 'HOSTS']);
            $this->store->db->delete('asset_links', ['source_id' => $id, 'kind' => 'BUILT_FROM']);
            if (!$this->inventory->get($hostId)) {
                $this->inventory->asset('linux', $hostKey, $location['target'] ?: $hostKey);
            }
            $this->inventory->link($hostId, 'HOSTS', $id, 'Registered executable');
            $this->inventory->link($id, 'BUILT_FROM', $source['id'], 'Operator source link');

            return $id;
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
        try {
            $this->repository->sourcePatch($source['data']['path'], $profile['revision'], $candidate);
        } catch (\DomainException $error) {
            throw new RemediationFieldError('candidate', $error->getMessage());
        }
        if (!hash_equals($profile['digest'], $this->digest($profile))) {
            throw new \DomainException('The installed executable changed. Confirm its source revision before queuing a new build.');
        }

        return $this->changes->queueBinary($source, $profile['revision'], [
            'binary' => $id, 'candidate' => $candidate, 'profile' => $profile,
        ], $binary['name']);
    }

    public function checkRetryTarget(Change $change): void
    {
        $plan = $change->data['plan'];
        $binary = $this->inventory->get($plan['binary'] ?? '');
        $profile = $plan['profile'] ?? [];
        if ('binary' !== ($binary['kind'] ?? null) || !is_string($profile['digest'] ?? null) || $binary['data'] != $profile) {
            throw new \DomainException('The executable registration changed. Reconfirm its source and build settings before preparing another candidate.');
        }
        if (!hash_equals($profile['digest'], $this->digest($profile))) {
            throw new \DomainException('The installed executable changed. Confirm its source revision before queuing a new build.');
        }
    }

    public function verify(Change $change): ?bool
    {
        if ('standalone-binary' !== $change->strategy) {
            throw new \DomainException('This remediation does not support executable installation verification.');
        }
        if ('approved' !== $change->getStatus()) {
            throw new \DomainException('deployed' === $change->getStatus()
                ? 'Installation is already verified. Refresh to view the recorded check.'
                : 'Approve the executable before verifying its installation.');
        }
        $plan = $change->data['plan'];
        try {
            $sha = $this->digest($plan['profile']);
        } catch (\DomainException $error) {
            $this->store->record($change->id, 'binary_installation_unavailable', ['note' => $error->getMessage()]);

            return null;
        }
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
            throw new RemediationFieldError('host', 'Choose a Linux host connection with a managed SSH credential.');
        }

        return $connection;
    }

    private function source(string $id): array
    {
        $source = $this->inventory->get($id);
        if ('repository' !== ($source['kind'] ?? null) || isset($source['data']['subdirectory'])
            || ($source['data']['role'] ?? '') === 'infrastructure') {
            throw new RemediationFieldError('repository', 'Choose a registered application repository root.');
        }

        return $source;
    }
}
