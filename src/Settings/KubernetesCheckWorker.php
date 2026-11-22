<?php
declare(strict_types=1);

namespace App\Settings;

use App\Discovery\KubernetesConnectionProbe;
use App\Discovery\RepositoryConnectionProbe;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final class KubernetesCheckWorker
{
    public function __construct(
        private readonly KubernetesChecks $checks,
        private readonly KubernetesConnectionProbe $probe,
        private readonly Connections $connections,
        private readonly RepositoryConnectionProbe $repositories,
    ) {
    }

    public function __invoke(RunKubernetesCheck $message): void
    {
        $queued = $this->checks->get($message->id);
        if (!$queued || 'queued' !== $queued['status']) {
            return;
        }
        $running = array_replace($queued, ['status' => 'running']);
        if (!$this->checks->update($message->id, $queued, $running)) {
            return;
        }

        try {
            $input = $queued['input'];
            $result = match ($queued['action']) {
                'repository' => $this->repositories->test($input),
                'contexts' => $this->probe->contexts($input),
                'namespaces' => $this->probe->availableNamespaces($input),
                default => $this->probe->test($input),
            };
            if ('contexts' === $queued['action']) {
                $result['contexts'] = array_map(static fn (string $name): array => ['name' => $name], $result['contexts']);
            }
            $status = 'complete';
        } catch (\DomainException $error) {
            $result = ['error' => $error->getMessage()];
            $status = 'failed';
        } catch (\Throwable) {
            $result = ['error' => 'The worker could not check the connection. Review the worker configuration and try again.'];
            $status = 'failed';
        }

        $checkedAt = gmdate(DATE_ATOM);
        if (!empty($queued['connection']) && ($connection = $this->connections->get($queued['connection']))) {
            $data = $connection['data'];
            $namespaces = Connections::clusterNamespaces($data);
            if ($connection['kind'] === 'cluster' && $data['target'] === $input['target']
                && ($data['credential'] ?? '') === $input['credential']
                && ($namespaces ?? []) === $input['namespaces']
                && (null === $namespaces) === ('all' === $input['namespaceMode'])) {
                $this->connections->update($connection, array_replace($data, [
                    'last_connection_test' => $checkedAt, 'test_passed' => $result['passed'] ?? false,
                    'test_endpoint' => $result['endpoint'] ?? ($data['test_endpoint'] ?? null),
                ]));
            }
        }
        $this->checks->update($message->id, $running, array_replace($running, [
            'status' => $status, 'checked_at' => $checkedAt,
            'result' => $result + ['worker' => gethostname() ?: 'Inventory worker'],
        ]));
    }
}
