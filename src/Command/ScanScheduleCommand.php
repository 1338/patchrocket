<?php
declare(strict_types=1);

namespace App\Command;

use App\Audit\Store;
use App\Intelligence\ScanSchedules;
use App\Settings\Connections;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:scan-schedule', 'Manage recurring scans for registered assets')]
final class ScanScheduleCommand extends Command
{
    public function __construct(private readonly ScanSchedules $schedules, private readonly Connections $connections)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'add, remove, list, or run-due');
        $this->addArgument('asset', InputArgument::OPTIONAL, 'Registered asset ID');
        $this->addOption('minutes', null, InputOption::VALUE_REQUIRED, 'Scan interval', '60');
        $this->addOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum due scans in one run', '5');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $action = $input->getArgument('action');
        if ('list' === $action) {
            $output->writeln(Store::json($this->schedules->all()), OutputInterface::OUTPUT_RAW);
        } elseif ('run-due' === $action) {
            $limit = $this->number($input->getOption('limit'));
            $results = $this->schedules->runDue($limit);
            $remaining = $limit - count($results);
            if ($remaining > 0) {
                $results += $this->connections->enqueueDue($remaining);
            }
            $output->writeln(Store::json($results), OutputInterface::OUTPUT_RAW);

            return in_array('failed', $results, true) ? Command::FAILURE : Command::SUCCESS;
        } elseif ('add' === $action || 'remove' === $action) {
            $id = $input->getArgument('asset') ?? throw new \InvalidArgumentException('This action requires an asset ID.');
            if ('add' === $action) {
                $this->schedules->add($id, $this->number($input->getOption('minutes')));
            } else {
                $this->schedules->remove($id);
            }
        } else {
            throw new \InvalidArgumentException('Unknown scheduling action.');
        }

        return Command::SUCCESS;
    }

    private function number(string $value): int
    {
        return filter_var($value, FILTER_VALIDATE_INT) ?: throw new \InvalidArgumentException('Expected a positive integer.');
    }
}
