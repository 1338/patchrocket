<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\SecretManagers;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;

final class ManagedCredentialsTest extends TestCase
{
    private string $directory;
    private ?string $path;
    private string|false $processPath;
    private Store $store;
    private SecretManagers $managers;
    private ConnectionCredentials $credentials;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir().'/patchrocket-manager-'.bin2hex(random_bytes(8));
        $filesystem = new Filesystem();
        $filesystem->mkdir($this->directory, 0700);
        foreach (['aws', 'az', 'gcloud', 'vault', 'op'] as $name) {
            $file = $this->directory.'/'.$name;
            $filesystem->dumpFile($file, <<<'SH'
#!/bin/sh
if [ "$2" = eks ]; then
    test "$AWS_ACCESS_KEY_ID" = fixture-id && test -z "${AWS_PROFILE:-}" || exit 3
    printf '%s' '{"status":{"token":"fixture-token"}}'
elif [ "$2" = put ]; then
    test "$#" = 6 && test "$3" = -mount=bound && test "$4" = -cas=0 && test "$6" = - || exit 3
    test "$VAULT_ADDR" = http://127.0.0.1:18200 && test "$VAULT_TOKEN" = fixture-write-token || exit 3
    test "$VAULT_DISABLE_REDIRECTS" = true && test "$VAULT_SKIP_VERIFY" = false || exit 3
    printf '%s' "$5" > "$PATCHROCKET_VAULT_FIXTURE.path"
    cat > "$PATCHROCKET_VAULT_FIXTURE.data"
elif [ "$3" = -mount=bound ]; then
    test "$VAULT_ADDR" = http://127.0.0.1:18200 && test "$VAULT_TOKEN" = fixture-read-token || exit 3
    test "$VAULT_DISABLE_REDIRECTS" = true && test "$VAULT_SKIP_VERIFY" = false || exit 3
    test -z "${VAULT_AGENT_ADDR:-}" || exit 3
    printf '%s' '{"resolved":true}'
else
    printf '%s' "$PATCHROCKET_CREDENTIAL_FIXTURE"
fi
SH);
            chmod($file, 0700);
        }
        $this->path = $_ENV['PATH'] ?? null;
        $this->processPath = getenv('PATH');
        $_ENV['PATH'] = $this->directory.':'.$this->processPath;
        putenv('PATH='.$_ENV['PATH']);
        $store = $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $scratch = new Repository(new Inventory($store));
        $this->managers = new SecretManagers($store, new AnsibleVault($scratch));
        $this->credentials = new ConnectionCredentials($this->managers, $scratch);
    }

    protected function tearDown(): void
    {
        if (null === $this->path) {
            unset($_ENV['PATH']);
        } else {
            $_ENV['PATH'] = $this->path;
        }
        putenv(false === $this->processPath ? 'PATH' : 'PATH='.$this->processPath);
        unset($_ENV['PATCHROCKET_CREDENTIAL_FIXTURE'], $_ENV['PATCHROCKET_VAULT_FIXTURE']);
        (new Filesystem())->remove($this->directory);
    }

    public function testSupportedProvidersResolveBundles(): void
    {
        $this->fixture(['value' => 'synthetic']);
        foreach ([
            ['aws', 'us-east-1', 'example/reference'],
            ['azure', '', 'https://example.vault.azure.net/secrets/reference'],
            ['gcp', 'example-project', 'reference'],
            ['vault', 'kv', 'example/reference'],
            ['onepassword', '', 'op://Testing/Reference/value'],
        ] as [$type, $scope, $locator]) {
            $this->managers->save($type, $type, $scope);
            self::assertSame(['value' => 'synthetic'], $this->managers->bundle($type.':'.$locator));
        }
    }

    public function testVaultUsesTheSavedAddressAndScopedTokenWhenEdited(): void
    {
        $previous = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = str_repeat('fixture-app-secret', 3);
        try {
            $this->managers->save('fixture', 'vault', 'bound', 'http://127.0.0.1:18200/', 'fixture-read-token');
            $this->managers->save('fixture', 'vault', 'bound', 'http://127.0.0.1:18200');
            $stored = $this->store->row('SELECT data FROM operator_settings WHERE id = ?', ['manager:fixture'])['data'];
            self::assertNotSame('fixture-read-token', $stored['token']);
            $shown = $this->managers->all()[0]['data'];
            self::assertTrue($shown['has_token']);
            self::assertArrayNotHasKey('token', $shown);
            self::assertSame(['resolved' => true], $this->managers->bundle('fixture:read-test'));

            $this->expectExceptionMessage('Enter a Vault token for this address.');
            $this->managers->save('fixture', 'vault', 'bound', 'https://new-vault.example.com');
        } finally {
            if (null === $previous) {
                unset($_SERVER['APP_SECRET']);
            } else {
                $_SERVER['APP_SECRET'] = $previous;
            }
        }
    }

    public function testVaultAddressRejectsRemoteHttp(): void
    {
        $this->expectExceptionMessage('Remote Vault servers require HTTPS.');
        $this->managers->save('fixture', 'vault', 'kv', 'http://vault.example.com:8200', 'fixture-token');
    }

    public function testVaultWritesTheBundleThroughStdinWithTheSelectedManagerAndSeparateToken(): void
    {
        $previous = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = str_repeat('fixture-app-secret', 3);
        $_ENV['PATCHROCKET_VAULT_FIXTURE'] = $this->directory.'/write';
        try {
            $this->managers->save('other', 'vault', 'other', 'http://127.0.0.1:18200', 'other-token');
            $this->managers->save('selected', 'vault', 'bound', 'http://127.0.0.1:18200', 'fixture-read-token', 'fixture-write-token');
            $this->managers->save('selected', 'vault', 'bound', 'http://127.0.0.1:18200');
            $bundle = '{"password":"synthetic-credential"}';
            $reference = $this->managers->storeVaultBundle('selected', $bundle);

            self::assertMatchesRegularExpression('~^selected:patchrocket/dashboard/[a-f0-9]{32}$~D', $reference);
            self::assertSame($reference, 'selected:'.file_get_contents($this->directory.'/write.path'));
            self::assertSame(['value' => $bundle], json_decode(file_get_contents($this->directory.'/write.data'), true));
            self::assertSame(['resolved' => true], $this->managers->bundle($reference));
            self::assertSame(['other', 'selected'], $this->managers->vaultDestinations());
            $manager = $this->managers->all()[1]['data'];
            self::assertTrue($manager['has_writer_token']);
            self::assertArrayNotHasKey('writer_token', $manager);
            self::assertStringNotContainsString('synthetic-credential', Store::json(
                $this->store->row('SELECT data FROM operator_settings WHERE id = ?', ['manager:selected']),
            ));
        } finally {
            if (null === $previous) {
                unset($_SERVER['APP_SECRET']);
            } else {
                $_SERVER['APP_SECRET'] = $previous;
            }
        }
    }

    public function testManagedSshUsesPrivateTemporaryFilesAndDisablesAmbientConfiguration(): void
    {
        $this->managers->save('fixture', 'vault', 'kv');
        $this->fixture(['private_key' => '-----BEGIN OPENSSH PRIVATE KEY-----', 'known_hosts' => 'example ssh-ed25519 fixture', 'port' => 2222]);
        $file = $this->credentials->ssh('fixture:ssh', static function (array $options): string {
            self::assertContains('/dev/null', $options);
            self::assertContains('IdentityAgent=none', $options);
            self::assertContains('2222', $options);
            $file = $options[array_search('-i', $options, true) + 1];
            self::assertSame(0600, fileperms($file) & 0777);

            return $file;
        });
        self::assertFileDoesNotExist($file);

        $this->credentials->ssh('fixture:ssh', static function (array $options): void {
            self::assertSame('2201', $options[array_search('-p', $options, true) + 1]);
        }, '2201');
    }

    public function testManagedKubeconfigRejectsExecAuthentication(): void
    {
        $this->managers->save('fixture', 'vault', 'kv');
        $this->fixture(['kubeconfig' => json_encode([
            'kind' => 'Config', 'contexts' => [['name' => 'target']],
            'users' => [['user' => ['exec' => ['command' => '/bin/false']]]],
        ], JSON_THROW_ON_ERROR)]);
        $this->expectExceptionMessage('inline token or certificate pair');
        $this->credentials->kubernetes('fixture:kube', 'target', static function (): never {
            self::fail('The exec kubeconfig must be rejected.');
        });
    }

    public function testEksUsesManagedAwsCredentialsAndStoresOnlyATemporaryKubeconfig(): void
    {
        $this->managers->save('fixture', 'vault', 'kv');
        $bundle = [
            'region' => 'us-east-1', 'cluster_name' => 'fixture', 'access_key_id' => 'fixture-id',
            'secret_access_key' => 'fixture-secret', 'server' => 'https://eks.example', 'ca_data' => 'Zml4dHVyZQ==',
        ];
        $this->fixture(['access_key_id' => 'offline-fixture-id'] + $bundle);
        $this->credentials->checkKubernetesReference('fixture:eks', null);

        $this->fixture($bundle);
        $path = $this->credentials->kubernetes('fixture:eks', 'target', static function (string $path): string {
            $data = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('fixture-token', $data['users'][0]['user']['token']);
            self::assertSame(0600, fileperms($path) & 0777);

            return $path;
        });
        self::assertFileDoesNotExist($path);
    }

    private function fixture(array $data): void
    {
        $_ENV['PATCHROCKET_CREDENTIAL_FIXTURE'] = json_encode($data, JSON_THROW_ON_ERROR);
    }
}
