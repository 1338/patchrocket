<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\MessageBusInterface;

#[AsMessageHandler]
final class IndependentVerification
{
    public const SETTINGS_PREFIX = 'independent-verification:';
    private const LEASE_SECONDS = 3600;

    public function __construct(
        private readonly Store $store,
        private readonly ApprovalPolicy $policy,
        private readonly Changes $changes,
        private readonly ChangeWorker $worker,
        private readonly MessageBusInterface $bus,
    ) {
    }

    /** @return array{state: string, note: ?string}|null */
    public function status(Change $change): ?array
    {
        $job = $this->get($change->id);
        if (!$job || $job['patch_sha256'] !== ($change->data['patch_sha256'] ?? null)) {
            return null;
        }

        return ['state' => self::state($job), 'note' => $job['note'] ?? null];
    }

    public static function hasCandidate(Change $change): bool
    {
        return 'awaiting_approval' === $change->getStatus()
            && is_string($change->data['patch'] ?? null)
            && is_string($change->data['patch_sha256'] ?? null)
            && '' !== $change->data['patch_sha256'];
    }

    public function queue(Change $change): void
    {
        if (!self::hasCandidate($change)) {
            throw new \DomainException('Independent verification requires a candidate patch awaiting approval.');
        }
        if (ApprovalPolicy::INDEPENDENT_VERIFICATION_REQUIRED !== ($this->policy->hold($change)['code'] ?? null)) {
            throw new \DomainException('The repository policy does not currently require independent verification of this candidate.');
        }

        $previous = $this->get($change->id);
        if ($previous && in_array(self::state($previous), ['queued', 'running'], true)) {
            throw new \DomainException('Independent verification is already queued or running.');
        }
        $job = [
            'id' => bin2hex(random_bytes(16)), 'patch_sha256' => $change->data['patch_sha256'],
            'state' => 'queued', 'updated_at' => gmdate(DATE_ATOM),
        ];
        $this->store->db->transactional(function () use ($change, $previous, $job): void {
            if (!$this->save($change->id, $previous, $job)) {
                throw new \DomainException('The independent verification request changed. Refresh and try again.');
            }
            $this->bus->dispatch(new RunIndependentVerification($change->id, $job['id']));
        });
    }

    public function __invoke(RunIndependentVerification $message): void
    {
        $job = $this->get($message->changeId);
        if (!$job || $job['id'] !== $message->jobId || !in_array(self::state($job), ['queued', 'interrupted'], true)) {
            return;
        }
        $running = array_replace($job, [
            'state' => 'running', 'lease_until' => time() + self::LEASE_SECONDS, 'updated_at' => gmdate(DATE_ATOM),
        ]);
        if (!$this->save($message->changeId, $job, $running)) {
            return;
        }

        try {
            $change = $this->changes->get($message->changeId);
            if (!$change || !self::hasCandidate($change) || $change->data['patch_sha256'] !== $job['patch_sha256']) {
                throw new \DomainException('The candidate changed or is no longer awaiting approval.');
            }
            $this->worker->independentlyVerify($change, fn (bool $passed): bool => $this->finish(
                $message->changeId, $running, $passed ? 'passed' : 'failed',
            ));
        } catch (\DomainException $error) {
            $this->finish($message->changeId, $running, 'failed', $error->getMessage());
        } catch (\Throwable) {
            $this->finish($message->changeId, $running, 'failed', 'The worker could not verify the candidate. Check the worker configuration and try again.');
        }
    }

    private static function state(array $job): string
    {
        return 'running' === $job['state'] && $job['lease_until'] <= time() ? 'interrupted' : $job['state'];
    }

    private function get(string $id): ?array
    {
        return $this->store->row('SELECT data FROM operator_settings WHERE id = ?', [self::SETTINGS_PREFIX.$id])['data'] ?? null;
    }

    private function finish(string $changeId, array $running, string $state, ?string $note = null): bool
    {
        return $this->save($changeId, $running, array_replace($running, [
            'state' => $state, 'note' => $note, 'updated_at' => gmdate(DATE_ATOM),
        ]));
    }

    private function save(string $changeId, ?array $previous, array $job): bool
    {
        $id = self::SETTINGS_PREFIX.$changeId;
        $data = Store::json($job);
        if (null === $previous) {
            return 1 === $this->store->db->executeStatement(
                'INSERT INTO operator_settings (id, data) VALUES (?, ?) ON CONFLICT (id) DO NOTHING',
                [$id, $data],
            );
        }

        return 1 === $this->store->db->update('operator_settings', ['data' => $data], ['id' => $id, 'data' => Store::json($previous)]);
    }
}
