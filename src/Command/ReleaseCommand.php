<?php
declare(strict_types=1);

namespace App\Command;

use App\Remediation\Changes;
use App\Secrets\ConnectionCredentials;
use App\Remediation\GitOps;
use App\Remediation\PullRequests;
use App\Remediation\ReleaseTracking;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:release', 'Publish an approved PR or prepare and observe a GitOps rollout')]
final class ReleaseCommand extends Command
{
    public function __construct(
        private readonly Changes $changes,
        private readonly PullRequests $pullRequests,
        private readonly GitOps $gitOps,
        private readonly ConnectionCredentials $credentials,
        private readonly ReleaseTracking $tracking,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'pr, manifest, observe-kubernetes, track, or track-due');
        $this->addArgument('change', InputArgument::OPTIONAL, 'Remediation change ID');
        foreach (['repository', 'base', 'manifest', 'context', 'namespace', 'deployment', 'container', 'image', 'credential'] as $option) {
            $this->addOption($option, null, InputOption::VALUE_REQUIRED);
        }
        $this->addOption('provider', null, InputOption::VALUE_REQUIRED, 'Repository provider for PR publication', 'github');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $action = $input->getArgument('action');
        if ('track-due' === $action) {
            foreach ($this->tracking->due() as $id => $message) {
                $output->writeln($id.' '.$message, OutputInterface::OUTPUT_RAW);
            }

            return Command::SUCCESS;
        }
        $id = $input->getArgument('change') ?: throw new \InvalidArgumentException('Supply the remediation change ID.');
        if ('track' === $action) {
            $output->writeln($this->tracking->check($id), OutputInterface::OUTPUT_RAW);

            return Command::SUCCESS;
        }
        $change = $this->changes->get($id) ?? throw new \DomainException('Unknown change ID.');
        $required = static fn (string $option): string => $input->getOption($option) ?: throw new \InvalidArgumentException('Supply --'.$option.'.');
        switch ($action) {
            case 'pr':
                $output->writeln($this->pullRequests->publish($change, $required('repository'), $required('base'),
                    $input->getOption('credential'), $input->getOption('provider')), OutputInterface::OUTPUT_RAW);
                break;
            case 'manifest':
                $output->write($this->gitOps->manifest($change, $required('manifest'), $required('container'), $required('image')), options: OutputInterface::OUTPUT_RAW);
                break;
            case 'observe-kubernetes':
                $context = $required('context');
                $observe = fn (?string $file): bool => $this->gitOps->observe($change, $context, $required('namespace'), $required('deployment'), $required('container'), $required('image'), $file);
                $credential = $input->getOption('credential');
                $passed = $credential ? $this->credentials->kubernetes($credential, $context, $observe) : $observe(null);
                $output->writeln($passed ? 'Running digest verified.' : 'The deployment has insufficient runtime evidence.');

                return $passed ? Command::SUCCESS : Command::FAILURE;
            default:
                throw new \InvalidArgumentException('Unknown release action.');
        }

        return Command::SUCCESS;
    }
}
