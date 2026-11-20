<?php
declare(strict_types=1);

namespace App\Command;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Discovery\HostCollector;
use App\Discovery\Repository;
use App\Intelligence\AssetScans;
use App\Secrets\ConnectionCredentials;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Messenger\Transport\SetupableTransportInterface;
use Symfony\Component\Filesystem\Filesystem;

#[AsCommand('patchrocket:inventory', 'Register, discover, and scan authorized assets')]
final class InventoryCommand extends Command
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Repository $repositories,
        private readonly Infrastructure $infrastructure,
        private readonly HostCollector $hosts,
        private readonly AssetScans $scans,
        private readonly ConnectionCredentials $credentials,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
        #[Autowire(service: 'messenger.transport.jobs')] private readonly SetupableTransportInterface $transport,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('action', InputArgument::REQUIRED, 'init, repository, linux, docker, linux-ssh, docker-ssh, linux-import, scan-linux-ssh, kubernetes, kubernetes-all, kubernetes-refresh, scan, scan-image, scan-registry, scan-observed, scan-running, link-repository, or list');
        $this->addArgument('value', InputArgument::OPTIONAL, 'Repository path, asset ID, image reference, or Kubernetes context');
        $this->addOption('credential', null, InputOption::VALUE_REQUIRED, 'Managed SSH or Kubernetes credential reference');
        $this->addOption('sudo', null, InputOption::VALUE_NONE, 'Use non-interactive sudo for remote Docker inventory');
        $this->addOption('editable', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Allow compatibility proposals to edit this src/ PHP file');
        $this->addOption('label', null, InputOption::VALUE_REQUIRED, 'Docker label filter');
        $this->addOption('repository', null, InputOption::VALUE_REQUIRED, 'Associate discovered images with a registered repository ID');
        $this->addOption('namespace', null, InputOption::VALUE_REQUIRED, 'Authorized Kubernetes namespace', 'default');
        $this->addOption('role', null, InputOption::VALUE_REQUIRED, 'Repository role: application or infrastructure');
        $this->addOption('infra-context', null, InputOption::VALUE_REQUIRED, 'Observed Kubernetes context used for exact infrastructure matches');
        $this->addOption('subdirectory', null, InputOption::VALUE_REQUIRED, 'Scan a committed application subdirectory');
        $this->addOption('relationship', null, InputOption::VALUE_REQUIRED, 'built-from, source, or deployment', 'built-from');
        $this->addOption('snapshot', null, InputOption::VALUE_REQUIRED, 'Path to an exported host inventory');
        $this->addOption('registry', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Allowed registry host. Repeat for multiple registries.');
        $this->addOption('scope', null, InputOption::VALUE_REQUIRED, 'Exact observed container scope, for example context/namespace');
        $this->addOption('refresh', null, InputOption::VALUE_NONE, 'Include images with a previous successful scan');
        $this->addOption('platform', null, InputOption::VALUE_REQUIRED, 'Registry image platform', 'linux/amd64');
        $this->addOption('demo', null, InputOption::VALUE_NONE, 'Use synthetic advisories for this fixture repository');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $value = $input->getArgument('value');
        $credential = $input->getOption('credential');
        $ssh = fn (callable $job): mixed => $credential ? $this->credentials->ssh($credential, $job) : $job([]);
        $kube = fn (callable $job): mixed => $credential ? $this->credentials->kubernetes($credential, $this->required($value), $job) : $job(null);
        switch ($input->getArgument('action')) {
            case 'init':
                $this->initializeSecret();
                $this->store->install();
                $this->transport->setup();
                break;
            case 'repository':
                $output->writeln($this->repositories->register($this->required($value), $input->getOption('editable'), $input->getOption('demo'), $input->getOption('subdirectory'), null, $input->getOption('role'), $input->getOption('infra-context')));
                break;
            case 'docker':
                $output->writeln((string) $this->infrastructure->docker($input->getOption('label'), $input->getOption('repository')));
                break;
            case 'kubernetes':
                $output->writeln((string) $kube(fn (?string $file): int => $this->infrastructure->kubernetes($this->required($value), $input->getOption('namespace'), $input->getOption('repository'), $file)));
                break;
            case 'kubernetes-all':
                $output->writeln(Store::json($kube(fn (?string $file): array => $this->infrastructure->kubernetesAll($this->required($value), $file))), OutputInterface::OUTPUT_RAW);
                break;
            case 'kubernetes-refresh':
                $results = $this->infrastructure->refreshClusters();
                $output->writeln(Store::json($results), OutputInterface::OUTPUT_RAW);

                return array_filter($results, static fn (array $result): bool => isset($result['error'])) ? Command::FAILURE : Command::SUCCESS;
            case 'linux':
                $output->writeln($this->hosts->local());
                break;
            case 'linux-ssh':
                $output->writeln($ssh(fn (array $options): string => $this->hosts->ssh($this->required($value), $options)));
                break;
            case 'docker-ssh':
                $output->writeln((string) $ssh(fn (array $options): int => $this->hosts->docker($this->required($value), $options, $input->getOption('sudo'))));
                break;
            case 'scan-linux-ssh':
                [$id, $count] = $this->scans->linuxSsh($this->hosts, $this->required($value));
                $output->writeln($id.' '.$count.' finding(s)');
                break;
            case 'linux-import':
                $output->writeln($this->hosts->import($this->required($value), $this->required($input->getOption('snapshot'))));
                break;
            case 'scan':
                $id = $this->required($value);
                $count = $this->scans->scan($id);
                $output->writeln($count.('infrastructure' === ($this->inventory->get($id)['data']['role'] ?? '') ? ' infrastructure declarations and references' : ' finding(s)'));
                break;
            case 'scan-image':
                $output->writeln($this->scans->localImage($this->required($value), $input->getOption('demo')).' finding(s)');
                break;
            case 'scan-observed':
                $output->writeln($this->scans->observedImage($this->required($value), $input->getOption('platform')).' finding(s)');
                break;
            case 'scan-running':
                $failed = false;
                $targets = iterator_to_array($this->scans->runningImages($input->getOption('registry'), $input->getOption('scope'), $input->getOption('refresh')));
                foreach ($targets as $id => $name) {
                    try {
                        $status = $this->scans->observedImage($id, $input->getOption('platform')).' finding(s)';
                    } catch (\Exception) {
                        $status = 'scan failed; see asset scan status';
                        $failed = true;
                    }
                    $output->writeln("$id $name $status", OutputInterface::OUTPUT_RAW);
                }

                return $failed ? Command::FAILURE : Command::SUCCESS;
            case 'link-repository':
                $this->inventory->associateRepository($this->required($value), $this->required($input->getOption('repository')), $input->getOption('relationship'));
                break;
            case 'scan-registry':
                $id = $this->scans->registerRegistryImage($this->required($value), $input->getOption('platform'), $input->getOption('repository'));
                $output->writeln($id.' '.$this->scans->scan($id).' finding(s)');
                break;
            case 'list':
                if (!$value) {
                    foreach ($this->store->rows('SELECT * FROM assets ORDER BY kind, name') as $asset) {
                        $output->writeln(implode(' ', [$asset['kind'], $asset['id'], $asset['name']]), OutputInterface::OUTPUT_RAW);
                    }
                }
                $findings = $this->store->rows(
                    'SELECT * FROM findings WHERE active = 1'.($value ? ' AND asset_id = ?' : '').' ORDER BY last_seen, id',
                    $value ? [$value] : [],
                );
                foreach ($findings as $finding) {
                    $output->writeln(implode(' ', ['finding', $finding['id'], $finding['data']['advisory'], $finding['data']['package']]), OutputInterface::OUTPUT_RAW);
                }
                break;
            default:
                throw new \InvalidArgumentException('Unknown inventory action.');
        }

        return Command::SUCCESS;
    }

    private function initializeSecret(): void
    {
        $path = $this->project.'/var/app-secret';
        if (isset($_SERVER['APP_SECRET']) || is_file($path)) {
            return;
        }
        $previous = umask(0077);
        try {
            (new Filesystem())->dumpFile($path, bin2hex(random_bytes(32))."\n");
        } finally {
            umask($previous);
        }
    }

    private function required(?string $value): string
    {
        return $value ?: throw new \InvalidArgumentException('This action requires a value.');
    }
}
