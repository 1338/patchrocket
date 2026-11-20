<?php
declare(strict_types=1);

use App\AI\Compatibility;
use App\Audit\Store;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;

final class CompatibilityTest extends TestCase
{
    private const ORIGINAL = "<?php\nreturn Legacy::method();\n";
    private const UPDATED = "<?php\nreturn Upgraded::method();\n";

    private string $workspace;

    protected function setUp(): void
    {
        $this->workspace = sys_get_temp_dir().'/patchrocket-test-'.bin2hex(random_bytes(8));
        (new Filesystem())->dumpFile($this->workspace.'/src/Adapter.php', self::ORIGINAL);
        (new Filesystem())->dumpFile($this->workspace.'/tests/Verification.php', "<?php\n");
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->workspace);
    }

    public function testOllamaWireResponseProducesScopedProposal(): void
    {
        $proposal = json_encode(['src/Adapter.php' => self::UPDATED], JSON_THROW_ON_ERROR);
        $requests = [];
        $http = new MockHttpClient(function (string $method, string $url) use ($proposal, &$requests): JsonMockResponse {
            $requests[] = parse_url($url, PHP_URL_PATH);

            return new JsonMockResponse('/api/show' === end($requests)
                ? ['capabilities' => ['completion']]
                : ['message' => ['content' => $proposal], 'done_reason' => 'stop']);
        });
        $provider = new Compatibility($http, 'ollama', 'fixture-model', 'http://localhost:11434', '', false, 2);

        self::assertSame(['src/Adapter.php'], $provider->propose(
            $this->workspace,
            ['src/Adapter.php'],
            ['package' => 'fixture/dependency', 'fixed' => '2.0.0'],
            [['log' => 'Legacy method has been removed.']],
            false,
        ));
        self::assertSame(['/api/show', '/api/chat'], $requests);
        self::assertSame(self::UPDATED, file_get_contents($this->workspace.'/src/Adapter.php'));
    }

    public function testOutOfScopeProposalLeavesAllFilesUntouched(): void
    {
        $proposal = json_encode([
            'src/Adapter.php' => self::UPDATED,
            'tests/Verification.php' => "<?php\nexit(0);\n",
        ], JSON_THROW_ON_ERROR);
        $http = new MockHttpClient([
            new JsonMockResponse(['capabilities' => ['completion']]),
            new JsonMockResponse(['message' => ['content' => $proposal]]),
        ]);
        $provider = new Compatibility($http, 'ollama', 'fixture-model', 'http://localhost:11434', '', false, 2);

        try {
            $provider->propose($this->workspace, ['src/Adapter.php'], [
                'package' => 'fixture/dependency', 'fixed' => '2.0.0',
            ], [], false);
            self::fail('Expected an out-of-scope proposal to be rejected.');
        } catch (DomainException) {
            self::assertSame(self::ORIGINAL, file_get_contents($this->workspace.'/src/Adapter.php'));
            self::assertSame("<?php\n", file_get_contents($this->workspace.'/tests/Verification.php'));
        }
    }

    public function testOpenAiRequiresSourceSharingConsentAndUsesResponsesApi(): void
    {
        $proposal = json_encode(['src/Adapter.php' => self::UPDATED], JSON_THROW_ON_ERROR);
        $requests = 0;
        $http = new MockHttpClient(function (string $method, string $url, array $options) use ($proposal, &$requests): JsonMockResponse {
            ++$requests;
            self::assertSame('POST', $method);
            self::assertSame('https://api.openai.com/v1/responses', $url);
            $body = json_decode($options['body'], true, flags: JSON_THROW_ON_ERROR);
            self::assertSame('gpt-6.2-sol', $body['model']);
            self::assertSame('high', $body['reasoning']['effort']);

            return new JsonMockResponse(['status' => 'completed', 'output' => [
                ['type' => 'message', 'content' => [['type' => 'output_text', 'text' => $proposal]]],
            ]]);
        });
        $key = 'sk-'.str_repeat('a', 64);
        $blocked = new Compatibility($http, 'openai', 'gpt-4o-mini', '', $key, false, 2);
        self::assertSame(0, $blocked->limit(false));
        self::assertSame(0, $requests);

        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $settings = new OperatorSettings($store);
        $settings->saveAi([
            'provider' => 'openai', 'model' => 'gpt-6.2-sol', 'endpoint' => 'http://localhost:11434',
            'limit' => 2, 'cloud_source' => '1', 'effort' => 'high',
        ]);
        $allowed = new Compatibility($http, 'off', '', '', $key, false, 0, $settings);
        self::assertSame(['src/Adapter.php'], $allowed->propose(
            $this->workspace, ['src/Adapter.php'], ['package' => 'fixture/dependency', 'fixed' => '2.0.0'], [], false,
        ));
        self::assertSame(1, $requests);
        self::assertSame(self::UPDATED, file_get_contents($this->workspace.'/src/Adapter.php'));
    }
}
