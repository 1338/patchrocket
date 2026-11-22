<?php
declare(strict_types=1);

namespace App\Remediation;

use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final class RegistryCleanupWorker
{
    public function __construct(
        private readonly RegistryCleanup $cleanup,
        private readonly RegistryCleanupClient $client,
        private readonly RegistryCleanupRuntime $runtime,
    ) {
    }

    public function __invoke(RunRegistryCleanup $message): void
    {
        $pending = $this->cleanup->job($message->id);
        if (!$pending || 'queued' !== $pending['status']) {
            return;
        }
        $job = array_replace($pending, ['status' => 'running']);
        $this->cleanup->transition($pending, $job, 'worker');

        try {
            $image = [$job['host'], $job['repository'], $job['digest']];
            if ($image !== $this->cleanup->candidate($job['asset']) || time() - $job['approved_at'] > 3600) {
                throw new \DomainException('The image has changed or the cleanup approval expired. Review it again.');
            }
            $settings = $this->cleanup->configuration($job['host']);
            if (!$settings || RegistryCleanup::configurationKey($settings) !== $job['configuration']) {
                throw new \DomainException('The registry cleanup configuration changed. Review the request again.');
            }
            $children = $this->client->confirm($image, $settings);
            $this->runtime->check($image, $settings, $children);
            $current = $this->cleanup->configuration($job['host']);
            if ($image !== $this->cleanup->candidate($job['asset']) || !$current
                || RegistryCleanup::configurationKey($current) !== $job['configuration']) {
                throw new \DomainException('The image or registry cleanup settings changed during the recheck.');
            }
            $url = $this->client->endpoint($image, $settings['provider']);
            $credential = $settings['credential'];
            $inspect = 'harbor' === $settings['provider'] ? 'GET' : 'HEAD';
            if (!in_array($this->client->request('DELETE', $url, $credential), [200, 202, 204], true)) {
                throw new \DomainException('The registry rejected artifact deletion. Check permissions and registry retention policies.');
            }
            $verified = false;
            for ($attempt = 0; $attempt < 3; ++$attempt) {
                if (404 === $this->client->request($inspect, $url, $credential)) {
                    $verified = true;
                    break;
                }
                if ($attempt < 2) {
                    sleep(1);
                }
            }
            if (!$verified) {
                throw new \DomainException('Deletion was accepted, but the worker could not verify that the artifact is absent.');
            }
            $outcome = ['status' => 'verified', 'result' => 'Registry confirmed the exact artifact is absent.'];
        } catch (\DomainException $error) {
            $outcome = ['status' => 'failed', 'result' => $error->getMessage()];
        } catch (\Throwable) {
            $outcome = ['status' => 'failed', 'result' => 'Cleanup could not be completed or verified. Review the registry and worker state.'];
        }

        $this->cleanup->transition($job, array_replace($job, $outcome, ['finished_at' => gmdate(DATE_ATOM)]), 'worker');
    }
}
