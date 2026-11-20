<?php
declare(strict_types=1);

namespace App\Command;

use App\Remediation\Changes;
use App\Remediation\Deployment;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:change', 'Prepare, approve, export, and track remediation')]
final class ChangeCommand extends Command
{
    public function __construct(private readonly Changes $changes, private readonly Deployment $deployment)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'queue, approve, patch, stage, observe, or show');
        $this->addArgument('id', InputArgument::REQUIRED, 'Finding ID for queue, change ID for other actions');
        $this->addArgument('target', InputArgument::OPTIONAL, 'Docker image for stage, container for observe');
        $this->addOption('strategy', null, InputOption::VALUE_REQUIRED, 'composer, npm, docker-base, or iac-image', 'composer');
        $this->addOption('repository', null, InputOption::VALUE_REQUIRED, 'Source repository ID for docker-base');
        $this->addOption('current', null, InputOption::VALUE_REQUIRED, 'Current base image reference');
        $this->addOption('fixed', null, InputOption::VALUE_REQUIRED, 'Digest-pinned replacement base image reference');
        $this->addOption('base', null, InputOption::VALUE_REQUIRED, 'Source branch for a traced image patch');
        $this->addOption('credential', null, InputOption::VALUE_REQUIRED, 'Managed Git credential reference for refreshing the source branch');
        $this->addOption('nginx-overlay', null, InputOption::VALUE_NONE, 'Replace the temporary nginx binary overlay with an updated unprivileged nginx base');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $action = $input->getArgument('action');
        $id = $input->getArgument('id');
        if ('queue' === $action) {
            $output->writeln($this->changes->queue($id, $input->getOption('strategy'), $input->getOption('repository'), [
                'current' => $input->getOption('current'), 'fixed' => $input->getOption('fixed'),
                'base' => $input->getOption('base'), 'credential' => $input->getOption('credential'),
                'nginx_overlay' => $input->getOption('nginx-overlay'),
            ]));

            return Command::SUCCESS;
        }

        $change = $this->changes->get($id) ?? throw new \DomainException('Unknown change ID.');
        switch ($action) {
            case 'approve':
                $this->changes->approve($change);
                break;
            case 'patch':
                if (!isset($change->data['patch'])) {
                    throw new \DomainException('No verified patch is available.');
                }
                $output->write($change->data['patch'], options: OutputInterface::OUTPUT_RAW);
                break;
            case 'stage':
                $output->writeln($this->deployment->stage($change, $input->getArgument('target') ?? throw new \InvalidArgumentException('Supply a rebuilt image.')));
                break;
            case 'observe':
                if (!$this->deployment->observe($change, $input->getArgument('target') ?? throw new \InvalidArgumentException('Supply a container.'))) {
                    $output->writeln('The container has not provided matching running-image and health evidence.');

                    return Command::FAILURE;
                }
                $output->writeln('Observed the verified digest.');
                break;
            case 'show':
                $output->writeln($change->getStatus());
                break;
            default:
                throw new \InvalidArgumentException('Unknown change action.');
        }

        return Command::SUCCESS;
    }
}
