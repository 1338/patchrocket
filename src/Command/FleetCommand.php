<?php
declare(strict_types=1);

namespace App\Command;

use App\Audit\Store;
use App\Fleet\Analysis;
use App\Fleet\BatchPlans;
use App\Fleet\RolloutSchedules;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:fleet', 'Analyze fleet exposure, plan batches, and schedule gated rollouts')]
final class FleetCommand extends Command
{
    public function __construct(
        private readonly Analysis $analysis,
        private readonly BatchPlans $batches,
        private readonly RolloutSchedules $rollouts,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'report, plan, schedule, cancel, schedules, or run-due');
        $this->addArgument('id', InputArgument::OPTIONAL, 'Advisory ID for plan, remediation ID for schedule or cancel');
        $this->addOption('repository', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY);
        foreach (['current', 'fixed', 'previous', 'replacement', 'not-before', 'canary'] as $option) {
            $this->addOption($option, null, InputOption::VALUE_REQUIRED);
        }
        $this->addOption('enqueue', null, InputOption::VALUE_NONE, 'Queue each eligible remediation for verification.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $id = static fn (): string => $input->getArgument('id') ?? throw new \InvalidArgumentException('Supply an ID.');
        $option = static fn (string $name): string => $input->getOption($name) ?: throw new \InvalidArgumentException('Supply --'.$name.'.');
        switch ($input->getArgument('action')) {
            case 'report':
                $result = $this->analysis->report();
                break;
            case 'plan':
                $result = $this->batches->plan($id(), $input->getOption('repository'), $input->getOption('current'), $input->getOption('fixed'), $input->getOption('enqueue'));
                break;
            case 'schedule':
                $timestamp = preg_replace('/Z$/D', '+00:00', $option('not-before'));
                $date = \DateTimeImmutable::createFromFormat(DATE_ATOM, $timestamp);
                if (!$date || $date->format(DATE_ATOM) !== $timestamp) {
                    throw new \InvalidArgumentException('Supply an RFC 3339 timestamp with an explicit offset.');
                }
                $this->rollouts->add($id(), $option('previous'), $option('replacement'), $date, $input->getOption('canary'));

                return Command::SUCCESS;
            case 'cancel':
                $this->rollouts->cancel($id());

                return Command::SUCCESS;
            case 'schedules':
                $result = $this->rollouts->all();
                break;
            case 'run-due':
                $result = $this->rollouts->runDue();
                $output->writeln(Store::json($result), OutputInterface::OUTPUT_RAW);

                return in_array('failed', $result, true) ? Command::FAILURE : Command::SUCCESS;
            default:
                throw new \InvalidArgumentException('Unknown fleet action.');
        }
        $output->writeln(Store::json($result), OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
