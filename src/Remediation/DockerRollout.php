<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Discovery\Infrastructure;
use Symfony\Component\Process\Process;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

final class DockerRollout
{
    public function __construct(
        private readonly Changes $changes,
        private readonly Store $store,
        private readonly Infrastructure $infra,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
    ) {
    }

    public function deploy(Change $change, string $previous, string $replacement): bool
    {
        $context = $this->context();
        $old = $this->infra->inspectContainer($previous);
        $new = $this->infra->inspectContainer($replacement);
        if ($old['id'] === $new['id'] || !$old['service'] || $old['service'] !== $new['service']
            || $old['image'] === $new['image'] || $new['image'] !== ($change->data['candidate_image'] ?? null)) {
            throw new \DomainException('Choose two containers for the same labeled service and the staged replacement digest.');
        }
        return $this->locked($context, $old['service'], function () use ($change, $context, $old, $new): bool {
            return $this->deployLocked($this->reload($change), $context, $old['id'], $new['id']);
        });
    }

    private function deployLocked(Change $change, string $context, string $previous, string $replacement): bool
    {
        $old = $this->infra->inspectContainer($previous);
        $new = $this->infra->inspectContainer($replacement);
        if (!$old['service'] || $old['service'] !== $new['service'] || $new['image'] !== ($change->data['candidate_image'] ?? null)) {
            throw new \DomainException('The rollout targets changed before execution.');
        }
        $target = [
            'context' => $context, 'previous' => $old['id'], 'replacement' => $new['id'],
            'rollback_image' => $old['image'], 'service' => $old['service'],
        ];
        if ('monitoring' === $change->getStatus()) {
            if (!$old['running'] || 'healthy' !== $old['health'] || empty($new['healthcheck']) || 'NONE' === $new['healthcheck'][0]) {
                throw new \DomainException('The previous container must be healthy and the replacement must have a healthcheck.');
            }
            $change->data['rollout'] = $target;
            if (!$this->changes->move($change, 'begin_rollout', 'Recorded the previous image and started a Docker rollout.')) {
                throw new \DomainException('Another operator advanced the rollout.');
            }
        } elseif ('rolling_out' !== $change->getStatus() || ($change->data['rollout'] ?? null) !== $target) {
            throw new \DomainException('Resume the rollout using its original Docker context and containers.');
        }
        try {
            $this->ensureRunning($new);
        } catch (\Exception $error) {
            $this->store->record($change->id, 'check', ['label' => 'Replacement health', 'passed' => false, 'round' => 0]);
            if ($this->healthy($old['id'], 0)) {
                $this->stop($new['id']);
                $this->changes->move($change, 'rollout_failed', 'Replacement failed startup or health checks. The previous container remains healthy.');
            }

            return false;
        }
        $this->stop($old['id']);
        $change->data['deployed_at'] = gmdate(DATE_ATOM);

        return $this->changes->move($change, 'observe', 'Replacement healthy at the approved digest. Previous container retained for rollback.');
    }

    public function rollback(Change $change): bool
    {
        $target = $change->data['rollout'] ?? null;
        if (!$target || $target['context'] !== $this->context()) {
            throw new \DomainException('The rollback requires the recorded Docker context and rollout.');
        }
        return $this->locked($target['context'], $target['service'], function () use ($change): bool {
            return $this->rollbackLocked($this->reload($change));
        });
    }

    private function rollbackLocked(Change $change): bool
    {
        $target = $change->data['rollout'];
        $old = $this->infra->inspectContainer($target['previous']);
        $new = $this->infra->inspectContainer($target['replacement']);
        if ($old['image'] !== $target['rollback_image'] || $new['image'] !== $change->data['candidate_image']
            || $old['service'] !== $target['service'] || $new['service'] !== $target['service']) {
            throw new \DomainException('The recorded rollout containers no longer match their expected images and service.');
        }
        if ('deployed' === $change->getStatus()) {
            if (!$this->changes->move($change, 'begin_rollback', 'Operator requested rollback to the previous digest.')) {
                throw new \DomainException('Another operator advanced the rollout.');
            }
        } elseif ('rolling_back' !== $change->getStatus()) {
            throw new \DomainException('Rollback requires a deployed change.');
        }

        try {
            $this->ensureRunning($old);
        } catch (\Exception) {
            $this->store->record($change->id, 'check', ['label' => 'Rollback health', 'passed' => false, 'round' => 0]);

            return false;
        }

        $this->stop($new['id']);
        $change->data['rolled_back_at'] = gmdate(DATE_ATOM);

        return $this->changes->move($change, 'confirm_rollback', 'Previous image restored and healthy. Replacement stopped.');
    }

    private function reload(Change $change): Change
    {
        return $this->changes->get($change->id) ?? throw new \DomainException('The change is unavailable.');
    }

    private function locked(string $context, string $service, callable $operation): bool
    {
        $directory = $this->project.'/var/rollout-locks';
        (new Filesystem())->mkdir($directory, 0700);
        $lock = fopen($directory.'/'.hash('sha256', $context."\0".$service), 'c');
        if (false === $lock) {
            throw new \RuntimeException('Could not open the rollout lock.');
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new \DomainException('A rollout for this service is already running.');
            }

            return $operation();
        } finally {
            fclose($lock);
        }
    }

    private function context(): string
    {
        return trim((new Process(['docker', 'context', 'show'], timeout: 10))->mustRun()->getOutput());
    }

    private function ensureRunning(array $container): void
    {
        if (!$container['running']) {
            (new Process(['docker', 'start', $container['id']], timeout: 30))->mustRun();
        }
        if (!$this->healthy($container['id'], 30)) {
            throw new \RuntimeException('Container did not become healthy.');
        }
    }

    private function healthy(string $id, int $seconds): bool
    {
        $deadline = time() + $seconds;
        do {
            $record = $this->infra->inspectContainer($id);
            if ($record['running'] && 'healthy' === $record['health']) {
                return true;
            }
            if (!$record['running'] || 'unhealthy' === $record['health'] || time() >= $deadline) {
                return false;
            }
            sleep(1);
        } while (true);
    }

    private function stop(string $id): void
    {
        if ($this->infra->inspectContainer($id)['running']) {
            (new Process(['docker', 'stop', '--time', '10', $id], timeout: 30))->mustRun();
        }
    }
}
