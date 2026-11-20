<?php
declare(strict_types=1);

namespace App\Command;

use App\Remediation\ApprovalPolicy;
use App\Remediation\Changes;
use App\Remediation\ChangeWorker;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:policy', 'Configure repository approval gates and independently verify candidates')]
final class PolicyCommand extends Command
{
    public function __construct(
        private readonly ApprovalPolicy $policy,
        private readonly Changes $changes,
        private readonly ChangeWorker $worker,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'configure or verify');
        $this->addArgument('id', InputArgument::REQUIRED, 'Repository ID to configure or change ID to verify');
        $this->addOption('allow', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Allowed strategy. Repeat to allow multiple strategies.');
        $this->addOption('independent', null, InputOption::VALUE_NONE, 'Require independent verification before approval.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $id = $input->getArgument('id');

        return match ($input->getArgument('action')) {
            'configure' => $this->configurePolicy($id, $input),
            'verify' => $this->verify($id, $output),
            default => throw new \InvalidArgumentException('Unknown policy action.'),
        };
    }

    private function configurePolicy(string $id, InputInterface $input): int
    {
        $this->policy->configure($id, $input->getOption('allow'), $input->getOption('independent'));

        return Command::SUCCESS;
    }

    private function verify(string $id, OutputInterface $output): int
    {
        $change = $this->changes->get($id) ?? throw new \DomainException('Unknown change ID.');
        $passed = $this->worker->independentlyVerify($change);
        $output->writeln($passed ? 'Independent verification passed.' : 'Independent verification failed. Review the change timeline.');

        return $passed ? Command::SUCCESS : Command::FAILURE;
    }
}
