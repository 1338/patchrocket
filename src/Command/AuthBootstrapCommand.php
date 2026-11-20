<?php
declare(strict_types=1);

namespace App\Command;

use App\Audit\Store;
use App\Auth\DashboardAccounts;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand('patchrocket:auth', 'Issue a one-time setup code for the first dashboard administrator')]
final class AuthBootstrapCommand extends Command
{
    public function __construct(private readonly Store $store, private readonly DashboardAccounts $accounts)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'bootstrap');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ('bootstrap' !== $input->getArgument('action')) {
            $output->writeln('Choose the bootstrap action.');
            return self::INVALID;
        }
        $this->store->install();
        try {
            $code = $this->accounts->issueBootstrap();
        } catch (\DomainException $error) {
            $output->writeln($error->getMessage());
            return self::FAILURE;
        }
        $output->writeln('Open /setup with the one-time code below. It expires in 30 minutes.');
        $output->writeln($code, OutputInterface::OUTPUT_RAW);

        return self::SUCCESS;
    }
}
