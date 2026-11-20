<?php
declare(strict_types=1);

namespace App\Command;

use App\AI\CodexFixture;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:codex-smoke', 'Run a synthetic smoke test through the development Codex CLI bridge')]
final class CodexSmokeCommand extends Command
{
    public function __construct(private readonly CodexFixture $codex)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('model', InputArgument::OPTIONAL, 'Codex model', 'gpt-6.2-sol');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $passed = $this->codex->smoke($input->getArgument('model'));
        } catch (\Throwable) {
            $passed = false;
        }
        $output->writeln($passed ? 'Codex CLI smoke test passed.' : 'Codex CLI smoke test failed. Check the CLI login and model availability.');

        return $passed ? Command::SUCCESS : Command::FAILURE;
    }
}
