<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\ArgoApplication;
use App\Discovery\DeploymentProvenance;
use App\Discovery\Repository;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class DeploymentProvenanceTest extends TestCase
{
    public function testInferenceUsesTheObservedCommitAndPrefersLiveArgoResourceStatus(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $provenance = new DeploymentProvenance($store, $inventory, $repository);
        $repository->temporary(function (string $git) use ($inventory, $repository, $provenance, $store): void {
            $fs = new Filesystem();
            $fs->dumpFile($git.'/web/Dockerfile', "FROM example.invalid/base\n");
            $fs->dumpFile($git.'/web/Jenkinsfile', <<<'JENKINS'
environment {
    REGISTRY = 'registry.example'
    IMAGE = "${REGISTRY}/apps/web"
}
shell --dockerfile "$WORKSPACE/web/Dockerfile" --destination "$IMAGE:$GIT_COMMIT"
JENKINS);
            (new Process(['git', 'init', '-q', $git]))->mustRun();
            (new Process(['git', '-C', $git, 'add', '--', 'web']))->mustRun();
            (new Process(['git', '-C', $git, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']))->mustRun();
            $revision = $repository->revision($git);
            $source = $repository->register($git, [], canonicalUrl: 'ssh://git@git.example/project/frontend.git');
            $infra = $inventory->asset('repository', 'infra', 'infra', ['role' => 'infrastructure']);
            $ns = 'apps';
            $workload = $inventory->asset('workload', 'web-uid', 'web', ['scope' => 'cluster/'.$ns, 'controller' => 'Deployment']);
            $pod = $inventory->asset('pod', 'pod-uid', 'pod');
            $imageRef = 'registry.example/apps/web';
            $digest = $imageRef.'@sha256:'.str_repeat('a', 64);
            $image = $inventory->asset('image', $digest, 'web');
            $container = $inventory->asset('container', 'pod-uid/web', 'web', [
                'running' => true, 'discovery_state' => 'observed', 'image' => $digest, 'reference' => $imageRef.':'.$revision,
            ]);
            $inventory->link($workload, 'HOSTS', $pod, 'Kubernetes');
            $inventory->link($pod, 'HOSTS', $container, 'Kubernetes');
            $inventory->link($container, 'RUNS', $image, 'Kubernetes');

            $application = [
                'metadata' => ['name' => 'web-production', 'namespace' => 'argocd'],
                'spec' => [
                    'destination' => ['server' => 'https://kubernetes.default.svc', 'namespace' => $ns],
                    'sources' => [
                        ['repoURL' => 'https://git.example/project/infra.git', 'path' => 'chart', 'helm' => [
                            'releaseName' => 'web', 'valueFiles' => ['$values/web/deploy/values.yaml'],
                            'parameters' => [['name' => 'image.tag', 'value' => str_repeat('c', 40)]],
                        ]],
                        ['repoURL' => 'https://credential:ignored@git.example/project/frontend.git', 'targetRevision' => 'main', 'ref' => 'values'],
                    ],
                ],
            ];
            $app = ArgoApplication::read($application, 'apps/web.yaml');
            self::assertSame('https://git.example/project/frontend.git', $app['sources'][1]['repository']);
            self::assertSame(['$values/web/deploy/values.yaml'], $app['sources'][0]['values_files']);
            $provenance->declare($infra, 'cluster', str_repeat('b', 40), [$app]);
            $build = $inventory->get($image)['data']['build_sources']['cluster'];
            self::assertSame([$source, $revision, 'web/Dockerfile', 'web/Jenkinsfile'], [$build['repository'], $build['revision'], $build['dockerfile'], $build['jenkinsfile']]);
            self::assertNull($store->row("SELECT kind FROM asset_links WHERE source_id = ? AND kind = 'BUILT_FROM'", [$image]));

            $application['status'] = [
                'resources' => [['namespace' => $ns, 'kind' => 'Deployment', 'name' => 'web']],
                'sync' => ['status' => 'Synced', 'revisions' => [str_repeat('b', 40), $revision]],
            ];
            $provenance->observe('cluster', 'argocd', [$application]);
            $link = $store->row("SELECT target_id, discovery FROM asset_links WHERE source_id = ? AND kind = 'MANAGED_BY'", [$workload]);
            self::assertSame('Argo CD resource inventory', $link['discovery']);
            $record = $inventory->get($link['target_id'])['data'];
            self::assertSame($revision, $record['observation']['sources'][1]['synced_revision']);
            self::assertSame(str_repeat('c', 40), $record['declarations'][$infra]['sources'][0]['image_tag']);

            $application['spec']['destination']['server'] = 'https://other-cluster.example';
            $provenance->observe('cluster', 'argocd', [$application]);
            self::assertSame([], $inventory->get($image)['data']['build_sources']);
            self::assertNull($store->row("SELECT kind FROM asset_links WHERE source_id = ? AND kind = 'BUILD_SOURCE'", [$image]));
        });
    }
}
