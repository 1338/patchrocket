<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\ArgoApplication;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use App\Remediation\HarborRelease;
use App\Remediation\IacImageUpgrade;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class IacImageUpgradeTest extends TestCase
{
    public function testArgoHelmOverridePatchesOnlyTheTracedImageTagAndKeepsTheValuesRevision(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $scanner = new Scanner($inventory, $store, 'unused');
        $upgrade = new IacImageUpgrade($store, $scanner, new HarborRelease($scanner, new OperatorSettings($store)));
        $repository = new Repository($inventory);
        $repository->temporary(function (string $path) use ($inventory, $upgrade, $repository): void {
            $file = 'apps/service.yaml';
            $yaml = <<<'YAML'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: service-demo
  namespace: argocd
spec:
  destination:
    server: https://kubernetes.default.svc
    namespace: demo
  sources:
  - repoURL: https://git.example/team/infra.git
    targetRevision: main
    path: charts/service
    helm:
      releaseName: service
      valueFiles:
      - $values/service/values.yaml
      parameters:
      - name: other
        value: 'old-tag'
      - name: image.tag
        value: 'old-tag' # Only this value should change.
  - repoURL: https://git.example/team/app.git
    targetRevision: old-tag
    ref: values
YAML;
            $fs = new Filesystem();
            $fs->dumpFile($path.'/'.$file, $yaml);
            $fs->dumpFile($path.'/charts/service/templates/deployment.yaml',
                '          image: "{{ required "image.repository is required" .Values.image.repository }}:{{ .Values.image.tag }}"'."\n");
            (new Process(['git', 'init', '-q', '-b', 'main'], $path))->mustRun();
            (new Process(['git', 'add', '.'], $path))->mustRun();
            (new Process(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], $path))->mustRun();
            $repo = $repository->register($path, [], role: 'infrastructure', infraContext: 'ctx',
                canonicalUrl: 'https://git.example/team/infra.git');
            $digest = 'registry.example/team/image@sha256:'.str_repeat('a', 64);
            $image = $inventory->asset('image', $digest, 'image', ['digest' => $digest, 'platform' => 'linux/amd64']);
            $container = $inventory->asset('container', 'one', 'app', [
                'running' => true, 'scope' => 'ctx/demo', 'reference' => 'registry.example/team/image:old-tag',
            ]);
            $pod = $inventory->asset('pod', 'one', 'app-one');
            $workload = $inventory->asset('workload', 'one', 'service');
            $application = Yaml::parse($yaml);
            $application['status'] = ['resources' => [['kind' => 'Deployment', 'name' => 'service', 'namespace' => 'demo']]];
            $argo = $inventory->asset('argo-application', 'one', 'service-demo', [
                'context' => 'ctx',
                'observation' => ArgoApplication::read($application),
                'declarations' => [$repo => ArgoApplication::read($application, $file)],
            ]);
            $inventory->link($container, 'RUNS', $image, 'fixture');
            $inventory->link($pod, 'HOSTS', $container, 'fixture');
            $inventory->link($workload, 'HOSTS', $pod, 'fixture');
            $inventory->link($workload, 'MANAGED_BY', $argo, 'fixture');
            $inventory->link($argo, 'DEPLOYED_FROM', $repo, 'fixture');

            $asset = $inventory->get($image);
            $target = $upgrade->target($asset);
            self::assertSame($repo, $target['asset']['id']);
            self::assertSame($file, $target['source']['file']);
            $fixedTag = 'new-tag@sha256:'.str_repeat('b', 64);
            $plan = $upgrade->plan($target['source'], $asset, 'registry.example/team/image:'.$fixedTag);
            $revision = $repository->revision($path);
            [$before, $after] = $upgrade->editCommitted($repository, $path, $revision, 'main', $plan);
            self::assertSame($yaml, $before);
            self::assertSame(str_replace("'old-tag' # Only", "'".$fixedTag."' # Only", $yaml), $after);

            $this->expectExceptionMessage('committed Argo CD sources differ');
            $upgrade->edit(str_replace('targetRevision: old-tag', 'targetRevision: drifted', $yaml), $plan);
        });
    }

    public function testObservedDeploymentIsTracedToOneManifestAndOnlyItsContainerIsEdited(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $settings = new OperatorSettings($store);
        $scanner = new Scanner($inventory, $store, 'unused');
        $upgrade = new IacImageUpgrade($store, $scanner, new HarborRelease($scanner, $settings));
        $current = 'docker.io/fixture/service:1.0';
        $digest = 'docker.io/fixture/service@sha256:'.str_repeat('a', 64);
        $fixed = 'docker.io/fixture/service:1.1@sha256:'.str_repeat('b', 64);
        $image = $inventory->asset('image', $digest, $current, ['digest' => $digest, 'platform' => 'linux/amd64']);
        $container = $inventory->asset('container', 'one', 'app', ['running' => true, 'scope' => 'ctx/demo', 'reference' => $current]);
        $pod = $inventory->asset('pod', 'one', 'app-one');
        $workload = $inventory->asset('workload', 'one', 'service');
        $repository = $inventory->asset('repository', 'infra', 'Infrastructure', [
            'role' => 'infrastructure', 'infra_context' => 'ctx', 'canonical_url' => 'https://bitbucket.org/fixture/infra.git',
            'infra_report' => ['resources' => [
                ['kind' => 'Deployment', 'namespace' => 'demo', 'name' => 'service', 'path' => 'platform/service.yaml', 'observed' => $workload],
            ]],
        ]);
        $inventory->link($container, 'RUNS', $image, 'fixture');
        $inventory->link($pod, 'HOSTS', $container, 'fixture');
        $inventory->link($workload, 'HOSTS', $pod, 'fixture');
        $inventory->link($workload, 'DEPLOYED_FROM', $repository, 'fixture');
        $asset = $inventory->get($image);
        $target = $upgrade->target($asset);
        self::assertSame($repository, $target['asset']['id']);
        self::assertSame('platform/service.yaml', $target['source']['file']);
        $plan = $upgrade->plan($target['source'], $asset, $fixed);
        $yaml = <<<YAML
# Keep this header.
apiVersion: v1
kind: ConfigMap
metadata:
  name: other
data:
  image: fixture/service:1.0
--- # deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: demo
  name: service
spec:
  template:
    spec:
      containers:
      - name: sidecar
        image: fixture/service:1.0
      - name: app
        image: 'fixture/service:1.0' # only this field changes
YAML;
        self::assertSame(
            str_replace("'fixture/service:1.0' # only this field changes", "'".$fixed."' # only this field changes", $yaml),
            $upgrade->edit($yaml, $plan),
        );
        $this->expectExceptionMessage('committed container image differs');
        $upgrade->edit(str_replace("'fixture/service:1.0'", "'fixture/service:1.2'", $yaml), $plan);
    }
}
