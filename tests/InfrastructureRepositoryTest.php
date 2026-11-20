<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\InfrastructureRepository;
use App\Discovery\DeploymentProvenance;
use App\Discovery\Repository;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class InfrastructureRepositoryTest extends TestCase
{
    public function testDeclarationsSeparateExternalReferencesAndOmitSecretValues(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $scan = new InfrastructureRepository($store, $inventory, $repository, new DeploymentProvenance($store, $inventory, $repository));
        $result = $scan->inspect([
            'deploy.yaml' => <<<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
---
apiVersion: v1
kind: Secret
metadata:
  name: credentials
data:
  secret: synthetic-secret-content
---
apiVersion: v1
kind: Service
metadata:
  name: legacy
  namespace: app
spec:
  type: ExternalName
  externalName: legacy.example
YAML,
            'app.yaml' => <<<'YAML'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: open-app
spec:
  source:
    repoURL: https://username:example-secret@git.example/config.git?token=synthetic
YAML,
            'cloud.tf.json' => '{"data":{"aws_vpc":{"external":{"sensitive":"synthetic"}}},"resource":{"aws_s3_bucket":{"logs":{}}}}',
            'templated.yaml' => '{{ .Values.config }}',
        ]);

        self::assertCount(5, $result['resources']);
        self::assertSame(['legacy.example', 'https://git.example/config.git', 'aws_vpc.external'], array_column($result['external'], 'target'));
        self::assertSame(['cloud.tf.json'], $result['terraform']);
        self::assertSame(1, $result['skipped']);
        self::assertStringNotContainsString('synthetic-secret-content', Store::json($result));
        self::assertStringNotContainsString('example-secret', Store::json($result));
    }

    public function testNamespacesComeFromLocalKustomizeResourcesAndMatchingArgoSources(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $scan = new InfrastructureRepository($store, $inventory, $repository, new DeploymentProvenance($store, $inventory, $repository));
        $workload = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n";
        $application = <<<'YAML'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: release
spec:
  destination:
    namespace: apps
    server: https://kubernetes.default.svc
  source:
    repoURL: https://git.example/project/infra.git
    path: cluster/plain
YAML;
        $result = $scan->inspect([
            'release.yaml' => $application,
            'foreign.yaml' => str_replace(
                ['project/infra.git', 'path: cluster/plain'],
                ['another/infra.git', 'path: cluster/external'],
                $application,
            ),
            'external/web.yaml' => $workload,
            'plain/web.yaml' => $workload,
            'overlay/web.yaml' => $workload,
            'overlay/unlisted.yaml' => $workload,
            'overlay/kustomization.yaml' => <<<'YAML'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: other
resources: [web.yaml]
YAML,
        ], 'git@git.example:project/infra.git', 'cluster');
        $workloads = array_column(array_filter($result['resources'], static fn (array $resource): bool => 'Deployment' === $resource['kind']), null, 'path');

        self::assertSame('', $workloads['external/web.yaml']['namespace']);
        self::assertSame('apps', $workloads['plain/web.yaml']['namespace']);
        self::assertSame('Argo CD', $workloads['plain/web.yaml']['namespace_from']);
        self::assertSame('other', $workloads['overlay/web.yaml']['namespace']);
        self::assertSame('Kustomize', $workloads['overlay/web.yaml']['namespace_from']);
        self::assertSame('', $workloads['overlay/unlisted.yaml']['namespace']);
    }
}
