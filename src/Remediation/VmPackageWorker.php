<?php
declare(strict_types=1);

namespace App\Remediation;

use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final class VmPackageWorker
{
    public function __construct(private readonly VmPackages $packages, private readonly VmPackageRunner $runner)
    {
    }

    public function __invoke(RunVmPackage $message): void
    {
        $job = $this->packages->job($message->asset);
        if (!$job || $job['id'] !== $message->id) {
            return;
        }
        $operation = $message->operation;
        $running = match ($operation) {
            'plan' => 'planning',
            'apply' => 'applying',
            'verify' => 'verifying',
        };
        if ($job['status'] === $running && time() - $job['updated_at'] > 1800) {
            // A recovered delivery must never repeat a possibly completed write.
            $this->finish($job, [
                'status' => 'plan' === $operation ? 'failed' : 'unverified',
                'result' => 'The worker was interrupted before recording a result.',
            ]);

            return;
        }
        if ($job['status'] !== $operation.'_queued') {
            return;
        }

        $claimed = array_replace($job, ['status' => $running, 'updated_at' => time()]);
        try {
            $this->packages->transition($job, $claimed, 'worker');
        } catch (\DomainException) {
            return;
        }

        $mayHaveWritten = 'verify' === $operation;
        try {
            $connection = $this->packages->jobConnection($claimed);
            if ('plan' === $operation) {
                $plan = $this->runner->run($connection, $claimed, 'plan');
                $result = [
                    'status' => 'awaiting_approval', 'plan' => $plan,
                    'expires_at' => $this->packages->reviewDeadline(), 'result' => '',
                ];
            } else {
                if ('apply' === $operation) {
                    if (time() >= $claimed['expires_at']) {
                        throw new \DomainException('The package approval expired before the worker started. Prepare a new plan.');
                    }
                    $mayHaveWritten = true;
                    $this->runner->run($connection, $claimed, 'apply');
                }
                $connection = $this->packages->jobConnection($claimed);
                $observed = $this->runner->run($connection, $claimed, 'observe');
                $plan = $claimed['plan'];
                $verified = $observed === array_intersect_key($plan, $observed);
                $result = [
                    'status' => $verified ? 'verified' : 'unverified',
                    'observed' => $observed + ['at' => gmdate(DATE_ATOM)],
                    'result' => $verified ? 'A fresh SSH check confirmed the approved package version.'
                        : 'The VM reported a different installed version. Review the evidence before starting another update.',
                ];
            }
        } catch (\DomainException $error) {
            $result = ['status' => $mayHaveWritten ? 'unverified' : 'failed', 'result' => $error->getMessage()];
        } catch (\Throwable) {
            $result = ['status' => $mayHaveWritten ? 'unverified' : 'failed', 'result' => 'The VM package operation did not complete. Check the worker and VM state.'];
        }
        $this->finish($claimed, $result);
    }

    private function finish(array $claimed, array $result): void
    {
        $this->packages->transition($claimed, array_replace($claimed, $result, ['updated_at' => time()]), 'worker');
    }
}
