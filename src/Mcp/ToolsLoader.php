<?php
declare(strict_types=1);

namespace App\Mcp;

use App\Remediation\RemediationFieldError;
use Mcp\Capability\Registry\Loader\LoaderInterface;
use Mcp\Capability\RegistryInterface;
use Mcp\Schema\Content\TextContent;
use Mcp\Schema\Request\CallToolRequest;
use Mcp\Schema\Result\CallToolResult;
use Mcp\Schema\Tool as Definition;
use Mcp\Server\RequestContext;
use Psr\Log\LoggerInterface;

final class ToolsLoader implements LoaderInterface
{
    private bool $write = false;

    public function __construct(
        private readonly WorkflowTools $workflow,
        private readonly ConfigurationTools $configuration,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function allowWrites(): void
    {
        $this->write = true;
    }

    public function load(RegistryInterface $registry): void
    {
        foreach ($this->workflow->tools() + $this->configuration->tools() as $name => $tool) {
            if (!$this->write && !$tool['annotations']['readOnlyHint']) {
                continue;
            }
            $registry->registerTool(Definition::fromArray(['name' => $name] + $tool),
                fn (RequestContext $context): CallToolResult => $this->invoke($name, $tool['run'], $context));
        }
    }

    private function invoke(string $name, callable $run, RequestContext $context): CallToolResult
    {
        $request = $context->getRequest();
        if (!$request instanceof CallToolRequest) {
            throw new \LogicException('The MCP capability requires a tool call.');
        }
        $failed = false;
        try {
            $data = $run($request->arguments);
        } catch (\DomainException | \InvalidArgumentException $error) {
            $failed = true;
            $data = ['error' => $error->getMessage()];
            if ($error instanceof RemediationFieldError) {
                $data['field'] = $error->field;
            }
        } catch (\Throwable $error) {
            $failed = true;
            $data = ['error' => 'PatchRocket could not complete the request. Check the server and worker logs.'];
            $this->logger->error('PatchRocket MCP tool failed.', ['tool' => $name, 'type' => $error::class]);
        }

        return new CallToolResult(
            [new TextContent(json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))],
            $failed,
            (object) $data,
        );
    }
}
