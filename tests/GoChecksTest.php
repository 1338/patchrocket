<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Settings\OperatorSettings;
use App\Verification\GoChecks;
use App\Verification\Sandbox;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;

final class GoChecksTest extends TestCase
{
    private string $root;
    private string $previousPath;
    private ?string $previousEnvPath;
    private GoChecks $checks;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/patchrocket-go-'.bin2hex(random_bytes(8));
        $filesystem = new Filesystem();
        $filesystem->dumpFile($this->root.'/work/go.mod', "module example.com/root\n");
        $filesystem->dumpFile($this->root.'/work/service/go.mod', "module example.com/service\n");
        $filesystem->dumpFile($this->root.'/bin/docker', <<<'SH'
#!/bin/sh
case "$*" in
  *"network inspect"*) echo bridge ;;
  *" test "*) test -f "$(dirname "$0")/pass-tests" ;;
esac
SH);
        chmod($this->root.'/bin/docker', 0700);
        $this->previousPath = getenv('PATH');
        $this->previousEnvPath = $_ENV['PATH'] ?? null;
        $_ENV['PATH'] = $this->root.'/bin:'.$this->previousPath;
        putenv('PATH='.$_ENV['PATH']);
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $this->checks = new GoChecks(new Sandbox('worker', 'resolver', new OperatorSettings($store)));
    }

    protected function tearDown(): void
    {
        putenv('PATH='.$this->previousPath);
        if (null === $this->previousEnvPath) {
            unset($_ENV['PATH']);
        } else {
            $_ENV['PATH'] = $this->previousEnvPath;
        }
        (new Filesystem())->remove($this->root);
    }

    public function testOnlyChangedGoModulesAreSelected(): void
    {
        self::assertSame([], $this->checks->modules($this->root.'/work', ['Dockerfile', 'package.json', 'README.md']));
        self::assertSame(['service'], $this->checks->modules($this->root.'/work', ['service/main.go', 'service/go.sum', 'README.md']));
        self::assertSame(['.', 'service'], $this->checks->modules($this->root.'/work', ['main.go', 'service/go.mod']));
        self::assertSame(['service'], $this->checks->modules($this->root.'/work', ['service/deleted.go']));
    }

    public function testUnchangedGoFilesDoNotRunChecks(): void
    {
        $this->checks->verify($this->root.'/work', $this->root, ['main.go' => 'same', 'Dockerfile' => 'old'],
            ['main.go' => 'same', 'Dockerfile' => 'new'], static function (): void { self::fail('Unrelated changes ran Go checks.'); });
        self::assertDirectoryDoesNotExist($this->root.'/go-cache-0');
    }

    public function testFailedTestsRecordEvidenceAndPreventBuild(): void
    {
        $evidence = [];
        try {
            $this->checks->verify($this->root.'/work', $this->root, ['main.go' => 'old'], ['main.go' => 'new'],
                static function (string $label, array $result) use (&$evidence): void { $evidence[$label] = $result['passed']; });
            self::fail('Failed Go tests were accepted.');
        } catch (DomainException $error) {
            self::assertStringContainsString('go test', $error->getMessage());
        }
        self::assertSame(['go mod download (.)' => true, 'go test -mod=readonly ./... (.)' => false], $evidence);
    }

    public function testSuccessfulModuleRecordsAllThreeChecks(): void
    {
        touch($this->root.'/bin/pass-tests');
        $evidence = [];
        $this->checks->verify($this->root.'/work', $this->root, ['main.go' => 'old'], ['main.go' => 'new'],
            static function (string $label, array $result) use (&$evidence): void { $evidence[$label] = $result['passed']; });
        self::assertSame([
            'go mod download (.)' => true,
            'go test -mod=readonly ./... (.)' => true,
            'go build -mod=readonly -o /tmp/go-output/ ./... (.)' => true,
        ], $evidence);
    }

    public function testWorkspaceChangesFailExplicitly(): void
    {
        $this->expectException(DomainException::class);
        $this->checks->modules($this->root.'/work', ['go.work']);
    }

    public function testGoFilesWithoutAModuleFailExplicitly(): void
    {
        unlink($this->root.'/work/go.mod');
        $this->expectException(DomainException::class);
        $this->checks->modules($this->root.'/work', ['main.go']);
    }
}
