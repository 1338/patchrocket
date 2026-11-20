<?php
declare(strict_types=1);

namespace App\Command;

use App\Remediation\Changes;
use App\Remediation\DockerRollout;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:rollout', 'Switch between staged Docker containers and roll back')]
final class RolloutCommand extends Command
{
    public function __construct(private readonly Changes $changes, private readonly DockerRollout $rollout)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'deploy or rollback');
        $this->addArgument('change', InputArgument::REQUIRED, 'Remediation change ID');
        $this->addArgument('previous', InputArgument::OPTIONAL, 'Previous Docker container');
        $this->addArgument('replacement', InputArgument::OPTIONAL, 'Staged replacement Docker container');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $change = $this->changes->get($input->getArgument('change')) ?? throw new \DomainException('Unknown change ID.');
        $passed = match ($input->getArgument('action')) {
            'deploy' => $this->rollout->deploy(
                $change,
                $input->getArgument('previous') ?? throw new \InvalidArgumentException('Supply the previous container.'),
                $input->getArgument('replacement') ?? throw new \InvalidArgumentException('Supply the replacement container.'),
            ),
            'rollback' => $this->rollout->rollback($change),
            default => throw new \InvalidArgumentException('Unknown rollout action.'),
        };
        $output->writeln($passed ? $this->changes->get($change->id)->getStatus() : 'Health verification failed. Review the change timeline.');

        return $passed ? Command::SUCCESS : Command::FAILURE;
    }
}
