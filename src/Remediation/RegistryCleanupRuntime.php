<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Discovery\KubernetesConnectionProbe;
use App\Settings\Connections;
use Symfony\Component\Process\Process;

final class RegistryCleanupRuntime
{
    public function __construct(
        private readonly Connections $connections,
        private readonly KubernetesConnectionProbe $probe,
        private readonly RegistryCleanupClient $client,
    ) {
    }

    public function check(array $image, array $settings, array $children): void
    {
        $checked = [];
        foreach ($this->connections->all() as $entry) {
            if ('cluster' !== $entry['kind']) {
                continue;
            }
            $data = $entry['data'];
            $scopes = Connections::clusterNamespaces($data);
            $credential = $data['credential'] ?? '';
            $this->probe->withVerifiedConnection([
                'target' => $data['target'], 'credentialMode' => $credential ? 'managed' : 'worker', 'credential' => $credential,
                'namespaceMode' => null === $scopes ? 'all' : 'selected', 'namespaces' => $scopes ?? [],
            ], function (string $config) use ($image, $settings, $entry, $data, $scopes, $children, &$checked): void {
                foreach ($scopes ?? [null] as $namespace) {
                    foreach ($this->images($config, $data['target'], $namespace, $entry['name']) as $reference) {
                        if (isset($checked[$reference])) {
                            continue;
                        }
                        $checked[$reference] = true;
                        $this->checkReference($reference, $image, $settings, $children);
                    }
                }
            });
        }
    }

    private function checkReference(string $reference, array $image, array $settings, array $children): void
    {
        [$host, $repository, $digest] = $image;
        $name = "$host/$repository";
        if ($reference === $digest || in_array($reference, $children, true)) {
            throw new \DomainException('Kubernetes reports this digest in a running container.');
        }
        if (!preg_match('~^'.preg_quote($name, '~').'(?:\:([A-Za-z0-9_.-]+))?(?:@(sha256:[a-f0-9]{64}))?$~D', $reference, $parts)) {
            return;
        }
        $ref = ($parts[2] ?? '') ?: (($parts[1] ?? '') ?: 'latest');
        if ($ref === $digest || in_array($ref, $children, true) || $this->client->referencesDigest($image, $settings, $ref, $digest)) {
            throw new \DomainException('A Kubernetes workload, job, or retained ReplicaSet still references this artifact.');
        }
    }

    private function images(string $config, string $context, ?string $namespace, string $name): iterable
    {
        try {
            $process = new Process(['kubectl', '--kubeconfig='.$config, '--context='.$context, '--request-timeout=12s',
                $namespace === null ? '--all-namespaces' : '--namespace='.$namespace,
                'get', 'pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs', '-o', 'json'], timeout: 20);
            $objects = json_decode($process->mustRun()->getOutput(), true, flags: JSON_THROW_ON_ERROR);
            if (!is_array($objects['items'] ?? null)) {
                throw new \RuntimeException('Invalid Kubernetes response.');
            }
        } catch (\Throwable) {
            throw new \DomainException('Could not check workload and rollback references on '.$name.'. Check inventory and batch resource read permissions.');
        }
        foreach ($objects['items'] as $object) {
            $spec = $object['spec'] ?? [];
            $spec = $spec['jobTemplate']['spec']['template']['spec'] ?? $spec['template']['spec'] ?? $spec;
            foreach (['containers', 'initContainers', 'ephemeralContainers'] as $key) {
                foreach ($spec[$key] ?? [] as $container) {
                    if (is_string($container['image'] ?? null)) {
                        yield $container['image'];
                    }
                }
            }
            foreach (['containerStatuses', 'initContainerStatuses', 'ephemeralContainerStatuses'] as $key) {
                foreach ($object['status'][$key] ?? [] as $container) {
                    if (is_string($container['imageID'] ?? null) && isset($container['state']['running'])) {
                        yield preg_replace('~^[a-z][a-z0-9+.-]*://~i', '', $container['imageID']);
                    }
                }
            }
        }
    }
}
