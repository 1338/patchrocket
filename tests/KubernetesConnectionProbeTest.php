<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\KubernetesConnectionProbe;
use App\Discovery\Repository;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\SecretManagers;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;

final class KubernetesConnectionProbeTest extends TestCase
{
    private Filesystem $files;
    private string $directory;
    private ?string $path;
    private KubernetesConnectionProbe $probe;

    protected function setUp(): void
    {
        $this->files = new Filesystem();
        $this->directory = sys_get_temp_dir().'/patchrocket-kube-probe-'.bin2hex(random_bytes(8));
        $this->files->mkdir($this->directory, 0700);
        $this->path = $_ENV['PATH'] ?? null;
        $_ENV['PATH'] = $this->directory.':'.getenv('PATH');
        $this->files->dumpFile($this->directory.'/kubectl', <<<'SCRIPT'
#!/usr/bin/env php
<?php
$fixture = json_decode(file_get_contents(__DIR__.'/fixture.json'), true, flags: JSON_THROW_ON_ERROR);
$args = array_slice($argv, 1);
$record = ['args' => $args];
$rawReview = ' --raw=/apis/authorization.k8s.io/v1/selfsubjectaccessreviews ';
if (str_contains(' '.implode(' ', $args).' ', $rawReview)) {
    $record['review'] = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
}
file_put_contents(__DIR__.'/calls', json_encode($record, JSON_THROW_ON_ERROR)."\n", FILE_APPEND);
if (getenv('KUBECTL_KUBERC') !== 'false') {
    exit(90);
}
if ($args === ['config', 'view', '-o', 'json']) {
    echo json_encode($fixture['config'], JSON_THROW_ON_ERROR);
    exit;
}
if ($args === ['--context=west', 'config', 'view', '--minify', '--flatten', '--raw', '-o', 'json']) {
    echo json_encode($fixture['selected'] ?? $fixture['config'], JSON_THROW_ON_ERROR);
    exit;
}
$path = substr($args[0], strlen('--kubeconfig='));
if (!str_starts_with($args[0], '--kubeconfig=') || !is_file($path) || (fileperms($path) & 0777) !== 0600
    || array_slice($args, 1, 3) !== ['--context=west', '--cache-dir='.dirname($path).'/cache', '--request-timeout=5s']) {
    exit(91);
}
if (array_slice($args, 4) === ['auth', 'whoami', '-o', 'json']) {
    if (isset($fixture['failure'])) {
        fwrite(STDERR, $fixture['failure']);
        exit(1);
    }
    echo json_encode(['kind' => 'SelfSubjectReview', 'status' => [
        'userInfo' => ['username' => $fixture['username'] ?? 'identity-private', 'extra' => ['private' => ['identity-secret']]],
    ]], JSON_THROW_ON_ERROR);
    exit;
}
if (array_slice($args, 4) === ['create', trim($rawReview), '-f', '-']) {
    $attributes = $record['review']['spec']['resourceAttributes'];
    $key = ($attributes['namespace'] ?? '*').'/'.$attributes['resource'];
    echo json_encode(['kind' => 'SelfSubjectAccessReview', 'status' => $fixture['reviews'][$key] ?? ['allowed' => true]], JSON_THROW_ON_ERROR);
    exit;
}
if (array_slice($args, 4) === ['get', 'namespaces', '-o', 'jsonpath={.items[*].metadata.name}']) {
    echo implode(' ', $fixture['namespaces'] ?? []);
    exit;
}
exit(92);
SCRIPT);
        $this->files->dumpFile($this->directory.'/vault', "#!/bin/sh\ncat \"\$(dirname \"\$0\")/bundle.json\"\n");
        chmod($this->directory.'/kubectl', 0700);
        chmod($this->directory.'/vault', 0700);

        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $scratch = new Repository(new Inventory($store));
        $managers = new SecretManagers($store, new AnsibleVault($scratch));
        $managers->save('fixture', 'vault', 'kv');
        $this->probe = new KubernetesConnectionProbe(new ConnectionCredentials($managers, $scratch), $managers, $scratch);
    }

    protected function tearDown(): void
    {
        if (null === $this->path) {
            unset($_ENV['PATH']);
        } else {
            $_ENV['PATH'] = $this->path;
        }
        $this->files->remove($this->directory);
    }

    public function testContextListingUsesOnlyMetadataForBothCredentialSources(): void
    {
        $config = $this->config();
        $config['contexts'][] = ['name' => 'alpha'];
        $config['contexts'][] = ['name' => "invalid\nname"];
        $config['users'][0]['user'] = ['exec' => ['command' => 'must-not-run']];
        $this->fixture(['config' => $config]);
        $this->managed($config);
        $expected = ['contexts' => ['alpha', 'west'], 'currentContext' => 'west'];

        self::assertSame($expected, $this->probe->contexts($this->selection()));
        self::assertSame($expected, $this->probe->contexts($this->managedSelection()));
        self::assertSame([['args' => ['config', 'view', '-o', 'json']]], $this->calls());
    }

    public function testNamespaceLookupReportsTheTotalAndSearchesBeforeApplyingTheLimit(): void
    {
        $namespaces = array_map(static fn (int $index): string => sprintf('team-%03d', $index), range(0, 502));
        $this->fixture(['config' => $this->config(), 'namespaces' => array_reverse($namespaces)]);

        self::assertSame([
            'namespaces' => array_slice($namespaces, 0, 500), 'namespaceCount' => 503,
        ], $this->probe->availableNamespaces($this->selection()));
        self::assertSame([
            'namespaces' => ['team-502'], 'namespaceCount' => 1, 'namespaceQuery' => '502',
        ], $this->probe->availableNamespaces($this->selection() + ['namespaceQuery' => '502']));
        self::assertSame([
            'namespaces' => [], 'namespaceCount' => 0, 'namespaceQuery' => 'missing',
        ], $this->probe->availableNamespaces($this->selection() + ['namespaceQuery' => 'missing']));
    }

    public function testWorkerTestReportsScopedPermissionsAndRedactsEndpointAndIdentity(): void
    {
        $this->fixture([
            'config' => $this->config('https://worker:server-secret@example.test:7443/routing-secret?key=query-secret'),
            'reviews' => [
                'team-b/pods' => ['allowed' => false, 'reason' => 'authorization-secret'],
                'team-b/replicasets' => ['allowed' => true, 'evaluationError' => 'evaluation-secret'],
            ],
        ]);
        $result = $this->probe->test($this->selection());

        self::assertSame('https://example.test:7443', $result['endpoint']);
        self::assertTrue($result['reachable']);
        self::assertTrue($result['authenticated']);
        self::assertFalse($result['passed']);
        self::assertSame(
            [true, true, true, true, true, true, true, true, null, false],
            array_column($result['permissions'], 'allowed'),
        );
        self::assertSame('list · pods · team-b', $result['permissions'][9]['label']);
        self::assertStringNotContainsString('secret', Store::json($result));
        self::assertStringNotContainsString('identity-private', Store::json($result));

        $calls = $this->calls();
        self::assertCount(12, $calls);
        self::assertSame('whoami', $calls[1]['args'][5]);
        $attributes = array_map(static fn (array $call): array => $call['review']['spec']['resourceAttributes'], array_slice($calls, 2));
        self::assertSame(['verb' => 'list', 'resource' => 'deployments', 'group' => 'apps', 'namespace' => 'team-a'], $attributes[0]);
        self::assertSame(['verb' => 'list', 'resource' => 'pods', 'group' => '', 'namespace' => 'team-b'], $attributes[9]);
        self::assertNotContains('namespaces', array_column($attributes, 'resource'));
    }

    public function testDiscoveryReceivesTheSamePrivateWorkerSnapshotAfterAllNamespaceChecks(): void
    {
        $this->fixture(['config' => $this->config()]);
        $selection = array_replace($this->selection(), ['namespaceMode' => 'all', 'namespaces' => []]);
        $path = $this->probe->withVerifiedConnection($selection, function (string $path): string {
            self::assertSame(0600, fileperms($path) & 0777);
            self::assertSame('west', json_decode(file_get_contents($path), true)['current-context']);
            $calls = $this->calls();
            self::assertCount(8, $calls);
            self::assertSame(['verb' => 'list', 'resource' => 'namespaces', 'group' => ''], $calls[2]['review']['spec']['resourceAttributes']);
            foreach (array_slice($calls, 1) as $call) {
                self::assertSame('--kubeconfig='.$path, $call['args'][0]);
            }
            foreach (array_slice($calls, 2) as $call) {
                self::assertArrayNotHasKey('namespace', $call['review']['spec']['resourceAttributes']);
            }

            return $path;
        });

        self::assertFileDoesNotExist($path);
    }

    public function testDiscoveryRechecksCurrentPermissionsAndStopsAfterRevocation(): void
    {
        $this->fixture(['config' => $this->config()]);
        self::assertTrue($this->probe->test($this->selection())['passed']);
        $this->fixture(['config' => $this->config(), 'reviews' => ['team-b/pods' => ['allowed' => false]]]);

        $this->expectExceptionMessage('The worker could not confirm all required Kubernetes list permissions.');
        $this->probe->withVerifiedConnection($this->selection(), static fn () => self::fail('Discovery must wait for verified access.'));
    }

    #[DataProvider('authenticationFailures')]
    public function testAuthenticationFailureDoesNotRequestPermissions(array $fixture, ?bool $reachable, ?bool $authenticated): void
    {
        $this->fixture($fixture + ['config' => $this->config()]);
        $result = $this->probe->test($this->selection());

        self::assertSame($reachable, $result['reachable']);
        self::assertSame($authenticated, $result['authenticated']);
        self::assertFalse($result['passed']);
        self::assertSame(array_fill(0, 10, null), array_column($result['permissions'], 'allowed'));
        self::assertCount(2, $this->calls());
        self::assertStringNotContainsString('diagnostic-secret', Store::json($result));
    }

    public static function authenticationFailures(): iterable
    {
        yield 'anonymous' => [['username' => 'system:anonymous'], true, false];
        yield 'rejected credentials' => [['failure' => 'error: You must be logged in to the server (diagnostic-secret)'], true, false];
        yield 'forbidden review' => [['failure' => 'error: the selfsubjectreviews API is not enabled in the cluster or you do not have permission to call it'], true, null];
        yield 'connection failure' => [['failure' => 'Unable to connect to the server: diagnostic-secret'], false, null];
        yield 'local plugin failure' => [['failure' => 'error: diagnostic-secret'], null, null];
    }

    public function testManagedTestReusesCredentialRestrictionsBeforeInvokingKubectl(): void
    {
        $config = $this->config();
        $config['users'][0]['user'] = ['exec' => ['command' => 'must-not-run']];
        $this->managed($config);
        try {
            $this->probe->test($this->managedSelection());
            self::fail('Expected managed credential validation to reject the exec plugin.');
        } catch (DomainException $error) {
            self::assertStringContainsString('inline token or certificate pair', $error->getMessage());
        }
        self::assertSame([], $this->calls());
    }

    public function testManagedDiscoveryReceivesOnlyTheValidatedContext(): void
    {
        $config = $this->config();
        $config['contexts'][] = ['name' => 'unused', 'context' => ['cluster' => 'primary', 'user' => 'worker']];
        $config['Users'] = [['name' => 'worker', 'user' => ['exec' => ['command' => 'must-not-run']]]];
        $this->managed($config);
        $this->fixture(['config' => $this->config()]);

        $path = $this->probe->withVerifiedConnection($this->managedSelection(), function (string $path): string {
            self::assertSame(0600, fileperms($path) & 0777);
            $config = json_decode(file_get_contents($path), true);
            self::assertSame(['west'], array_column($config['contexts'], 'name'));
            self::assertSame(['token' => 'synthetic-token'], $config['users'][0]['user']);
            self::assertArrayNotHasKey('Users', $config);
            self::assertSame('--kubeconfig='.$path, $this->calls()[0]['args'][0]);

            return $path;
        });
        self::assertFileDoesNotExist($path);
    }

    public function testWorkerSelectionMustMatchTheConfigurationSnapshot(): void
    {
        $this->fixture(['selected' => array_replace($this->config(), ['current-context' => 'other'])]);

        $this->expectExceptionMessage('The worker kubeconfig must include the selected context.');
        $this->probe->test($this->selection());
    }

    private function config(string $server = 'https://example.test'): array
    {
        return [
            'apiVersion' => 'v1', 'kind' => 'Config', 'current-context' => 'west',
            'contexts' => [['name' => 'west', 'context' => ['cluster' => 'primary', 'user' => 'worker']]],
            'clusters' => [['name' => 'primary', 'cluster' => ['server' => $server]]],
            'users' => [['name' => 'worker', 'user' => ['token' => 'synthetic-token']]],
        ];
    }

    private function selection(): array
    {
        return ['credentialMode' => 'worker', 'target' => 'west', 'namespaceMode' => 'selected', 'namespaces' => ['team-a', 'team-b']];
    }

    private function managedSelection(): array
    {
        return array_replace($this->selection(), ['credentialMode' => 'managed', 'credential' => 'fixture:kubeconfig']);
    }

    private function fixture(array $data): void
    {
        $this->files->dumpFile($this->directory.'/fixture.json', Store::json($data));
    }

    private function managed(array $config): void
    {
        $this->files->dumpFile($this->directory.'/bundle.json', Store::json(['kubeconfig' => Store::json($config)]));
    }

    private function calls(): array
    {
        $path = $this->directory.'/calls';

        return is_file($path) ? array_map(static fn (string $line): array => json_decode($line, true), file($path)) : [];
    }
}
