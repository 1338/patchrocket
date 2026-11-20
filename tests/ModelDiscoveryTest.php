<?php
declare(strict_types=1);

use App\AI\ModelDiscovery;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;

final class ModelDiscoveryTest extends TestCase
{
    public function testOllamaUsesServerCapabilitiesForTheSelectedModel(): void
    {
        $http = new MockHttpClient([
            new JsonMockResponse(['models' => [['name' => 'gpt-oss:20b'], ['name' => 'qwen3:8b']]]),
            new JsonMockResponse(['capabilities' => ['thinking'], 'details' => ['family' => 'gptoss']]),
            new JsonMockResponse(['capabilities' => ['thinking'], 'details' => ['family' => 'qwen3']]),
            new JsonMockResponse(['capabilities' => ['completion']]),
        ]);
        $service = new ModelDiscovery($http);
        $endpoint = 'http://localhost:11434';
        self::assertSame(['gpt-oss:20b', 'qwen3:8b'], $service->discover('ollama', $endpoint, '', '')['models']);
        self::assertSame(['low', 'medium', 'high'], $service->discover('ollama', $endpoint, '', 'gpt-oss:20b')['efforts']);
        self::assertSame(['off', 'on'], $service->discover('ollama', $endpoint, '', 'qwen3:8b')['efforts']);
        self::assertSame([], $service->discover('ollama', $endpoint, '', 'plain:latest')['efforts']);
    }

    public function testOpenAiUsesProviderDefaultForAModelWithoutKnownEffortSupport(): void
    {
        $service = new ModelDiscovery(new MockHttpClient([new JsonMockResponse(['data' => [
            ['id' => 'gpt-6.2-sol'], ['id' => 'gpt-4o-mini'], ['id' => 'gpt-image-1'],
        ]])]));
        self::assertSame(['gpt-4o-mini', 'gpt-6.2-sol'], $service->discover('openai', '', 'fixture', '')['models']);
        self::assertSame([], $service->discover('openai', '', '', 'gpt-4o-mini')['efforts']);
        self::assertContains('high', $service->discover('openai', '', '', 'gpt-6.2-sol')['efforts']);
    }
}
