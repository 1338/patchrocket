<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\KubernetesConnectionProbe;
use App\Discovery\Repository;
use App\Remediation\RegistryCleanup;
use App\Remediation\RegistryCleanupClient;
use App\Remediation\RegistryCleanupRuntime;
use App\Remediation\RegistryCleanupWorker;
use App\Remediation\RunRegistryCleanup;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Messenger\MessageBus;

final class RegistryCleanupTest extends TestCase
{
    public static function providers(): iterable
    {
        yield 'Harbor' => ['harbor', '/api/v2.0/projects/team/repositories/nested%252Fapp/artifacts/sha256%3A', 'GET'];
        yield 'OCI Distribution' => ['oci', '/v2/team/nested/app/manifests/sha256:', 'HEAD'];
    }

    #[DataProvider('providers')]
    public function testApprovalAndWorkerDeleteAndVerifyExactArtifact(string $provider, string $route, string $inspect): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $bus = new MessageBus();
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $secrets = new SecretManagers($store, new AnsibleVault($repository));
        $secrets->save('fixture', 'onepassword', '');
        $cleanup = new RegistryCleanup($store, $inventory, $bus);
        $host = 'registry.example.test';
        $digest = 'sha256:'.str_repeat('a', 64);
        $target = $host.'/team/nested/app@'.$digest;
        $asset = $inventory->asset('image', $target, $target, ['digest' => $target]);
        $cleanup->configure($host, $provider, 'fixture:op://vault/item/field');
        $id = $cleanup->propose($asset, 'requester');
        try {
            $cleanup->approve($id, $digest, 'admin', false);
            self::fail('Expected review requirement.');
        } catch (DomainException) {
            self::assertSame('awaiting_approval', $cleanup->job($id)['status']);
        }
        $cleanup->approve($id, $digest, 'admin', true);

        $calls = [];
        $http = new MockHttpClient(static function (string $method, string $url, array $options) use ($host, $route, $digest, &$calls): MockResponse {
            self::assertSame('https://'.$host.$route.str_repeat('a', 64), $url);
            self::assertSame(0, $options['max_redirects']);
            $calls[] = $method;

            return match (count($calls)) {
                1 => new MockResponse(json_encode(['digest' => $digest], JSON_THROW_ON_ERROR), ['response_headers' => ['Docker-Content-Digest: '.$digest]]),
                2 => new MockResponse('', ['http_code' => 202]),
                default => new MockResponse('', ['http_code' => 404]),
            };
        });

        $filesystem = new Filesystem();
        $directory = sys_get_temp_dir().'/patchrocket-cleanup-'.bin2hex(random_bytes(8));
        $filesystem->mkdir($directory, 0700);
        $filesystem->dumpFile($directory.'/op', "#!/bin/sh\nprintf '%s' '{\"username\":\"fixture\",\"token\":\"fixture-token\"}'");
        chmod($directory.'/op', 0700);
        $previousEnvPath = $_ENV['PATH'] ?? null;
        $path = getenv('PATH');
        putenv('PATH='.$directory.':'.$path);
        $_ENV['PATH'] = $directory.':'.$path;
        try {
            $client = new RegistryCleanupClient($http, $secrets);
            $runtime = new RegistryCleanupRuntime(new Connections($store, $bus),
                new KubernetesConnectionProbe(new ConnectionCredentials($secrets, $repository), $secrets, $repository), $client);
            $worker = new RegistryCleanupWorker($cleanup, $client, $runtime);
            $worker(new RunRegistryCleanup($id));
            $worker(new RunRegistryCleanup($id));
            self::assertSame(['GET', 'DELETE', $inspect], $calls);
            self::assertSame('verified', $cleanup->job($id)['status']);
            self::assertSame('admin', $cleanup->job($id)['approved_by']);
            self::assertSame(4, (int) $store->db->fetchOne("SELECT count(*) FROM audit WHERE change_id = 'registry-cleanup'"));
        } finally {
            $path === false ? putenv('PATH') : putenv('PATH='.$path);
            if ($previousEnvPath === null) {
                unset($_ENV['PATH']);
            } else {
                $_ENV['PATH'] = $previousEnvPath;
            }
            $filesystem->remove($directory);
        }
    }

    public function testRunningDigestBlocksRequestEvenWhenObservedThroughAnAlias(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $digest = 'registry.example.test/team/app@sha256:'.str_repeat('b', 64);
        $asset = $inventory->asset('image', 'digest', $digest, ['digest' => $digest]);
        $alias = $inventory->asset('image', 'tag', 'registry.example.test/team/app:current', ['digest' => $digest]);
        $container = $inventory->asset('container', 'fixture', 'Running fixture', ['running' => true]);
        $inventory->link($container, 'RUNS', $alias, 'Kubernetes');

        $this->expectExceptionMessage('observed this digest in a running container');
        (new RegistryCleanup($store, $inventory, new MessageBus()))->propose($asset, 'requester');
    }
}
