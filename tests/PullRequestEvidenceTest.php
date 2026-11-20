<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Remediation\BitbucketPullRequests;
use App\Remediation\Change;
use App\Remediation\PullRequests;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;

final class PullRequestEvidenceTest extends TestCase
{
    private Store $store;
    private PullRequests $publisher;
    private Change $change;

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $class = new ReflectionClass(PullRequests::class);
        $this->publisher = $class->newInstanceWithoutConstructor();
        $class->getProperty('store')->setValue($this->publisher, $this->store);
        $this->change = new Change('fixture', 'npm', 'awaiting_approval', [
            'revision' => str_repeat('a', 40), 'patch' => 'patch', 'patch_sha256' => hash('sha256', 'patch'),
        ]);
    }

    public function testMissingEvidenceBlocksPublication(): void
    {
        $this->expectExceptionMessage('passing recorded verification checks');
        $this->publisher->evidence($this->change);
    }

    public function testLatestFailureBlocksPublication(): void
    {
        $this->store->record('fixture', 'check', ['label' => 'Dependency rescan', 'passed' => true]);
        $this->store->record('fixture', 'check', ['label' => 'Dependency rescan', 'passed' => false]);
        $this->expectExceptionMessage('passing recorded verification checks');
        $this->publisher->evidence($this->change);
    }

    public function testEvidenceIncludesChecksAndExactPatchIdentity(): void
    {
        $this->store->record('fixture', 'check', ['label' => 'npm test', 'passed' => false]);
        $this->store->record('fixture', 'check', ['label' => 'npm test', 'passed' => true]);
        $body = $this->publisher->evidence($this->change);
        self::assertStringContainsString('Passed: npm test', $body);
        self::assertStringContainsString($this->change->data['patch_sha256'], $body);
        self::assertStringContainsString($this->change->data['revision'], $body);
        $this->change->data['patch'] = 'tampered';
        $this->expectExceptionMessage('intact patch');
        $this->publisher->evidence($this->change);
    }

    public function testMergeActionRequiresAdministratorRole(): void
    {
        $class = new ReflectionClass(\App\Auth\DashboardGuard::class);
        $guard = $class->newInstanceWithoutConstructor();
        $request = \Symfony\Component\HttpFoundation\Request::create('/remediations/fixture/pull-request', 'POST');
        foreach (['viewer' => false, 'operator' => false, 'admin' => true] as $role => $expected) {
            self::assertSame($expected, $class->getMethod('allowed')->invoke($guard, $request, 'change_pull_request', $role));
        }
    }

    public function testMergeChecksProviderHeadAndRecordsOnlyConfirmedMerge(): void
    {
        $root = sys_get_temp_dir().'/patchrocket-pr-'.bin2hex(random_bytes(8));
        mkdir($root, 0700);
        file_put_contents($root.'/vault', "#!/bin/sh\nprintf '%s' \"\$PR_TEST_BUNDLE\"\n");
        chmod($root.'/vault', 0700);
        $processPath = getenv('PATH');
        $oldPath = $_ENV['PATH'] ?? null;
        $_ENV['PATH'] = $root.':'.getenv('PATH');
        putenv('PATH='.$_ENV['PATH']);
        try {
            $inventory = new \App\Asset\Inventory($this->store);
            $repository = new \App\Discovery\Repository($inventory);
            $managers = new \App\Secrets\SecretManagers($this->store, new \App\Secrets\AnsibleVault($repository));
            $managers->save('fixture', 'vault', 'kv');
            $connections = new \App\Settings\Connections($this->store, new \Symfony\Component\Messenger\MessageBus());
            $git = new \App\Secrets\ManagedGit($managers, $root);
            $this->change->setStatus('approved');
            $this->store->record('fixture', 'check', ['label' => 'Dependency rescan', 'passed' => true]);
            foreach (['github', 'bitbucket'] as $provider) {
                $github = $provider === 'github';
                $url = 'https://'.($github ? 'github.com' : 'bitbucket.org').'/team/repo.git';
                $_ENV['PR_TEST_BUNDLE'] = json_encode(['repository' => $url, 'username' => 'x-token-auth', 'token' => 'fixture']);
                $this->store->put('inventory_connections', ['id' => 'connection', 'kind' => 'repository', 'name' => 'Repository',
                    'data' => Store::json(['target' => $url, 'credential' => 'fixture:repo'])]);
                $head = str_repeat('b', 40);
                $this->store->record('fixture', 'export', ['url' => str_replace('.git', $github ? '/pull/1' : '/pull-requests/1', $url),
                    'provider' => $provider, 'repository' => 'team/repo', 'base' => 'main', 'head' => $head,
                    'patch_sha256' => $this->change->data['patch_sha256']]);
                foreach ([true, false] as $tampered) {
                    $writes = 0;
                    $http = new MockHttpClient(function (string $method, string $endpoint, array $options) use ($github, $head, $tampered, &$writes): JsonMockResponse {
                        if ('GET' === $method) {
                            $observed = $tampered ? str_repeat('c', 40) : $head;
                            return new JsonMockResponse($github ? [
                                'state' => 'open', 'draft' => false,
                                'head' => ['sha' => $observed, 'ref' => 'patchrocket/fixture', 'repo' => ['full_name' => 'team/repo']],
                                'base' => ['ref' => 'main', 'sha' => $this->change->data['revision']],
                            ] : [
                                'state' => 'OPEN', 'draft' => false,
                                'source' => ['commit' => ['hash' => $observed], 'branch' => ['name' => 'patchrocket/fixture'], 'repository' => ['full_name' => 'team/repo']],
                                'destination' => ['branch' => ['name' => 'main'], 'commit' => ['hash' => $this->change->data['revision']]],
                            ]);
                        }
                        ++$writes;
                        self::assertSame($github ? 'PUT' : 'POST', $method);
                        self::assertStringEndsWith('/merge', $endpoint);
                        if ($github) {
                            self::assertSame($head, json_decode($options['body'], true)['sha']);
                        }
                        return new JsonMockResponse($github ? ['merged' => true] : ['state' => 'MERGED']);
                    });
                    $service = new \App\Remediation\DashboardPullRequests($this->store, $connections, $git, $this->publisher,
                        new \App\Remediation\ApprovalPolicy($this->store, $inventory), $http);
                    try {
                        self::assertStringContainsString('merged', $service->merge($this->change, 'connection'));
                        self::assertFalse($tampered);
                        self::assertSame(1, $writes);
                    } catch (\DomainException $error) {
                        self::assertTrue($tampered, $error->getMessage());
                        self::assertStringContainsString('no longer matches', $error->getMessage());
                        self::assertSame(0, $writes);
                    }
                }
            }
            self::assertSame('approved', $this->change->getStatus());
            self::assertCount(2, $this->store->rows("SELECT * FROM audit WHERE kind = 'merge'"));
        } finally {
            if (null === $oldPath) { unset($_ENV['PATH']); } else { $_ENV['PATH'] = $oldPath; }
            putenv(false === $processPath ? 'PATH' : 'PATH='.$processPath);
            unset($_ENV['PR_TEST_BUNDLE']);
            unlink($root.'/vault');
            rmdir($root);
        }
    }

    public function testBitbucketCreatesReadyPullRequestWithEvidence(): void
    {
        $url = 'https://bitbucket.org/team/repo/pull-requests/1';
        $http = new MockHttpClient(static function (string $method, string $endpoint, array $options) use ($url): JsonMockResponse {
            self::assertSame('POST', $method);
            $body = json_decode($options['body'], true, flags: JSON_THROW_ON_ERROR);
            self::assertFalse($body['draft']);
            self::assertSame('recorded evidence', $body['description']);
            return new JsonMockResponse(['links' => ['html' => ['href' => $url]]], ['http_code' => 201]);
        });
        self::assertSame($url, (new BitbucketPullRequests($http))->create('team/repo', 'main', 'patchrocket/fixture', 'token', 'Remediation', 'recorded evidence'));
    }
}
