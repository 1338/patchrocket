<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class GitOps
{
    public function __construct(private readonly Changes $changes, private readonly Store $store)
    {
    }

    public function manifest(Change $change, string $source, string $container, string $image): string
    {
        if ('monitoring' !== $change->getStatus() || !in_array($image, $change->data['candidate_registry_digests'] ?? [], true)) {
            throw new \DomainException('Choose a registry digest associated with the staged image.');
        }
        if (!is_file($source) || filesize($source) > 1000000) {
            throw new \InvalidArgumentException('Choose a Deployment YAML file smaller than 1 MB.');
        }
        $manifest = Yaml::parseFile($source);
        if ('apps/v1' !== ($manifest['apiVersion'] ?? null) || 'Deployment' !== ($manifest['kind'] ?? null)
            || !is_array($manifest['spec']['template']['spec']['containers'] ?? null)) {
            throw new \DomainException('Expected one Kubernetes apps/v1 Deployment.');
        }
        $containers = &$manifest['spec']['template']['spec']['containers'];
        $matches = array_keys(array_filter($containers, static fn (array $entry): bool => ($entry['name'] ?? null) === $container));
        if (1 !== count($matches)) {
            throw new \DomainException('The named container must occur exactly once.');
        }
        $containers[$matches[0]]['image'] = $image;

        return Yaml::dump($manifest, 20, 2);
    }

    public function observe(Change $change, string $context, string $namespace, string $deployment, string $container, string $image, ?string $config = null): bool
    {
        if ('monitoring' !== $change->getStatus() || !in_array($image, $change->data['candidate_registry_digests'] ?? [], true)) {
            throw new \DomainException('Choose a registry digest associated with the staged image.');
        }
        $registered = $this->store->row('SELECT id FROM assets WHERE id = ?', [hash('sha256', "namespace/$context/$namespace")]);
        if (!$registered || !preg_match('/^[a-z0-9][a-z0-9.-]{0,252}$/D', $deployment)) {
            throw new \DomainException('Register the Kubernetes scope and supply a deployment name.');
        }

        $result = $this->rolloutEvidence($context, $namespace, $deployment, $container, [$image], [$image], $config);
        $this->store->record($change->id, 'check', [
            'label' => 'Kubernetes running image', 'passed' => $result['passed'], 'round' => 0,
            'log' => "$context/$namespace/$deployment · {$result['ready']}/{$result['expected']} ready at $image",
        ]);
        if ($result['passed']) {
            $change->data['deployed_at'] = gmdate(DATE_ATOM);
        }

        return $result['passed'] && $this->changes->move($change, 'observe', 'Observed the verified registry digest in every replica of the selected Kubernetes deployment.');
    }

    public function rolloutEvidence(string $context, string $namespace, string $deployment, string $container, array $declaredImages, array $runtimeImages, ?string $config): array
    {
        if (!preg_match('/^[a-z0-9][a-z0-9.-]{0,252}$/D', $deployment)) {
            throw new \DomainException('Choose a valid Kubernetes Deployment name.');
        }
        $base = ['kubectl', ...($config ? ['--kubeconfig='.$config, '--cache-dir='.dirname($config).'/cache'] : []), '--context='.$context, '--namespace='.$namespace, '--request-timeout=20s', 'get'];
        $state = $this->get([...$base, 'deployment', $deployment, '-o', 'json'], 'the Deployment', 'metadata');
        if (!is_string($state['metadata']['uid'] ?? null) || !is_int($state['metadata']['generation'] ?? null)) {
            throw new \DomainException('Kubernetes returned incomplete Deployment metadata.');
        }
        $replicas = $this->get([...$base, 'replicasets', '-o', 'json'], 'ReplicaSets', 'items')['items'];
        $pods = $this->get([...$base, 'pods', '-o', 'json'], 'pods', 'items')['items'];
        $owners = [];
        foreach ($replicas as $replica) {
            if ($this->owner($replica) === $state['metadata']['uid']) {
                $owners[$replica['metadata']['uid']] = true;
            }
        }
        $expected = $state['spec']['replicas'] ?? 1;
        $ready = 0;
        $unexpected = 0;
        foreach ($pods as $pod) {
            if (!isset($owners[$this->owner($pod)]) || in_array($pod['status']['phase'] ?? '', ['Succeeded', 'Failed'], true)) {
                continue;
            }
            $statuses = array_column($pod['status']['containerStatuses'] ?? [], null, 'name');
            $actual = $statuses[$container] ?? [];
            $runtimeImage = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $actual['imageID'] ?? '');
            $conditions = array_column($pod['status']['conditions'] ?? [], 'status', 'type');
            if (($actual['ready'] ?? false) && 'True' === ($conditions['Ready'] ?? 'True') && isset($actual['state']['running'])
                && in_array($runtimeImage, $runtimeImages, true) && !isset($pod['metadata']['deletionTimestamp'])) {
                ++$ready;
            } else {
                ++$unexpected;
            }
        }
        $declared = array_column($state['spec']['template']['spec']['containers'] ?? [], 'image', 'name');
        $checks = [
            'The Deployment requests no replicas.' => $expected > 0,
            'The Deployment template has a different container image.' => in_array($declared[$container] ?? null, $declaredImages, true),
            'Kubernetes has yet to observe the current Deployment generation.' => ($state['status']['observedGeneration'] ?? 0) === $state['metadata']['generation'],
            'The available replica count differs from the requested count.' => ($state['status']['availableReplicas'] ?? $ready) === $expected,
            'The ready replica count at the verified digest differs from the requested count.' => $expected === $ready,
            'Some active pods are terminating or have no ready container at the verified digest.' => 0 === $unexpected,
        ];
        $issues = array_keys(array_filter($checks, static fn (bool $passed): bool => !$passed));
        $passed = [] === $issues;

        return compact('passed', 'expected', 'ready', 'unexpected', 'issues');
    }

    public function observeIac(Change $change, string $config, ?string $connectionId = null, ?string $connectionName = null): bool
    {
        if ('iac-image' !== $change->strategy || 'approved' !== $change->getStatus() || empty($change->data['image_verification']['image'])) {
            throw new \DomainException('Approve the infrastructure update before verifying the deployed digest.');
        }
        $plan = $change->data['plan'];
        $image = $change->data['image_verification']['image'];
        $evidence = $this->rolloutEvidence($plan['context'], $plan['namespace'], $plan['deployment'], $plan['container'],
            [$plan['fixed'], $image], [$image], $config);

        return $this->store->db->transactional(function () use ($change, $evidence, $image, $connectionId, $connectionName): bool {
            $this->store->record($change->id, 'rollout_check', $evidence + [
                'label' => 'IaC rollout digest', 'round' => 0, 'connection' => $connectionId, 'image' => $image,
                'connection_name' => $connectionName,
                'log' => $evidence['ready'].'/'.$evidence['expected'].' ready at '.$image,
            ]);
            if (!$evidence['passed']) {
                return false;
            }
            $change->data['deployed_at'] = gmdate(DATE_ATOM);

            return $this->changes->move($change, 'verify_iac_rollout', 'Observed the verified upstream digest in all ready Kubernetes replicas.');
        });
    }

    private function owner(array $object): ?string
    {
        foreach ($object['metadata']['ownerReferences'] ?? [] as $owner) {
            if ($owner['controller'] ?? false) {
                return $owner['uid'];
            }
        }

        return null;
    }

    private function get(array $args, string $resource, string $requiredField): array
    {
        try {
            $data = json_decode((new Process($args, timeout: 25))->mustRun()->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        } catch (ExceptionInterface) {
            throw new \DomainException('Could not read '.$resource.' from Kubernetes. Check the connection and read permissions.');
        } catch (\JsonException) {
            throw new \DomainException('Could not decode the Kubernetes response for '.$resource.'.');
        }
        if (!is_array($data[$requiredField] ?? null)) {
            throw new \DomainException('Kubernetes returned incomplete data for '.$resource.'.');
        }

        return $data;
    }
}
