<?php
declare(strict_types=1);

namespace App\Command;

use App\Mcp\ToolsLoader;
use Mcp\Server\Transport\StdioTransport;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireServiceClosure;

#[AsCommand('patchrocket:mcp', 'Serve PatchRocket tools over the local MCP stdio transport')]
final class McpCommand extends Command
{
    public function __construct(
        #[AutowireServiceClosure('mcp.server.patchrocket')] private readonly \Closure $server,
        private readonly ToolsLoader $tools,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('write', null, InputOption::VALUE_NONE, 'Allow the MCP client to configure integrations and run operator workflow actions');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        ini_set('display_errors', 'stderr');
        if ($input->getOption('write')) {
            $this->tools->allowWrites();
        }
        // The transport owns these handles; leave the Console application's streams open.
        $in = fopen('php://stdin', 'rb');
        $out = fopen('php://stdout', 'wb');
        if (false === $in || false === $out) {
            throw new \RuntimeException('The MCP command requires standard input and output.');
        }
        ($this->server)()->run(new StdioTransport($in, $out));

        return Command::SUCCESS;
    }
}
