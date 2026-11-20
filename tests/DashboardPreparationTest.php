<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use App\Remediation\ApprovalPolicy;
use App\Remediation\Changes;
use App\Remediation\ComposerUpgrade;
use App\Remediation\DashboardPreparation;
use App\Remediation\DockerBaseUpgrade;
use App\Remediation\NpmUpgrade;
use App\Secrets\AnsibleVault;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\OperatorSettings;
use App\Verification\Sandbox;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Process\Process;
use Symfony\Component\Workflow\Definition;
use Symfony\Component\Workflow\Workflow;

final class DashboardPreparationTest extends TestCase
{
    public function testTracedImagePlanQueuesOnceAcrossCoveredAdvisoriesAndCanRetry(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $repositories = new Repository($inventory);
        $repositories->temporary(function (string $root) use ($store, $inventory, $repositories): void {
            $url = 'https://bitbucket.example/team/source.git';
            $image = 'harbor.example/project/module';
            $fs = new Filesystem();
            $fs->dumpFile($root.'/module/Dockerfile', <<<'DOCKERFILE'
ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/library/nginx:1.30.0-alpine AS nginx-patched
FROM ${BASE_REGISTRY}/nginxinc/nginx-unprivileged:1.30-alpine
COPY --from=nginx-patched /usr/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-patched /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY dist /usr/share/nginx/html
DOCKERFILE);
            $fs->dumpFile($root.'/module/Jenkinsfile', <<<PIPELINE
IMAGE = '$image'
build --dockerfile "\$WORKSPACE/module/Dockerfile" --destination "\$IMAGE:\$GIT_COMMIT"
PIPELINE);
            (new Process(['git', '-C', $root, 'init', '-q', '-b', 'main']))->mustRun();
            (new Process(['git', '-C', $root, 'add', '.']))->mustRun();
            (new Process(['git', '-C', $root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'add module']))->mustRun();
            $revision = $repositories->revision($root);
            (new Process(['git', '-C', $root, 'update-ref', 'refs/remotes/origin/main', $revision]))->mustRun();
            $source = $repositories->register($root, [], sourceUrl: $url);
            $digest = $image.'@sha256:'.str_repeat('a', 64);
            $asset = $inventory->asset('image', $digest, $image, [
                'digest' => $digest, 'platform' => 'linux/amd64', 'build_sources' => [
                    ['repository' => $source, 'revision' => $revision, 'dockerfile' => 'module/Dockerfile', 'jenkinsfile' => 'module/Jenkinsfile'],
                ],
            ]);
            $finding = ['package' => 'nginx', 'type' => 'alpine', 'version' => '1.30.6-r1', 'fixed' => '1.30.7-r0', 'target' => $digest];
            $inventory->findings($asset, 'fixture', [['advisory' => 'CVE-fixture-1'] + $finding, ['advisory' => 'CVE-fixture-2'] + $finding]);
            $findings = $store->rows('SELECT * FROM findings ORDER BY id');

            $bus = new class implements MessageBusInterface {
                public array $messages = [];

                public function dispatch(object $message, array $stamps = []): Envelope
                {
                    $this->messages[] = $message;

                    return Envelope::wrap($message, $stamps);
                }
            };
            $managers = new SecretManagers($store, new AnsibleVault($repositories));
            $sandbox = new Sandbox('unused', 'none', new OperatorSettings($store));
            $changes = new Changes($store, $inventory, $repositories, new ComposerUpgrade($sandbox, new Scanner($inventory, $store, 'unused')),
                new DockerBaseUpgrade(), new NpmUpgrade($sandbox), $bus, new ApprovalPolicy($store, $inventory),
                new ManagedGit($managers, $root), new Workflow(new Definition(['queued'], [])));
            $form = new DashboardPreparation($store, $inventory, $changes, new Connections($store, $bus));
            self::assertTrue($form->form($findings[0], $inventory->get($asset))['overlay']);
            $inputs = [
                'base' => 'main',
                'fixed' => 'docker.io/nginx/nginx-unprivileged:1.30.7-alpine@sha256:'.str_repeat('b', 64),
                'node_image' => 'sha256:'.str_repeat('c', 64),
            ];
            $first = $form->start($findings[0]['id'], $inputs);
            self::assertSame($first, $form->start($findings[1]['id'], $inputs));
            self::assertCount(1, $bus->messages);
            $change = $changes->get($first);
            self::assertSame('docker-base', $change->strategy);
            self::assertSame($digest, $change->data['observed_image']);
            self::assertSame($revision, $change->data['revision']);
            self::assertSame(['CVE-fixture-1', 'CVE-fixture-2'], $change->data['plan']['advisories']);

            $store->db->update('changes', ['status' => 'failed'], ['id' => $first]);
            $second = $form->start($findings[0]['id'], $inputs);
            self::assertNotSame($first, $second);
            self::assertSame($second, $form->start($findings[0]['id'], $inputs));
            self::assertCount(2, $bus->messages);
        });
    }
}
