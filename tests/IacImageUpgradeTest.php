<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Intelligence\Scanner;
use App\Remediation\HarborRelease;
use App\Remediation\IacImageUpgrade;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class IacImageUpgradeTest extends TestCase
{
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
