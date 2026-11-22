<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\ConnectionCredentials;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

final class VmPackageRunner
{
    private const ERRORS = [
        'unsupported_os' => 'The SSH host did not report Ubuntu or Debian.',
        'missing_identity' => 'The host has no machine ID for binding the approval to this VM.',
        'not_installed' => 'The selected package is not installed.',
        'ambiguous_package' => 'Multiple architectures match. Select a package with its architecture.',
        'identity_changed' => 'The VM identity or package architecture changed.',
        'version_changed' => 'The installed version or repository candidate changed. Prepare a new plan.',
        'held_package' => 'The selected package is held.',
        'unhealthy_packages' => 'dpkg reported pending or inconsistent package state.',
        'no_upgrade' => 'There is no newer candidate in the host’s current APT indexes.',
        'simulation_failed' => 'APT could not simulate the exact upgrade using the host’s current indexes.',
        'additional_changes' => 'The simulation requires changes outside this package or could not confirm the single-package upgrade.',
        'busy' => 'Another PatchRocket package update is in progress on this VM.',
        'install_failed' => 'APT did not complete the install. Check the VM’s package manager logs.',
    ];

    public function __construct(
        private readonly ConnectionCredentials $credentials,
        private readonly Repository $scratch,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
    ) {
    }

    public function run(array $connection, array $job, string $operation): array
    {
        [$user, $host] = explode('@', $connection['target'], 2);
        $plan = $job['plan'] ?? [];
        $variables = [
            'operation' => $operation, 'package' => $job['package'],
            'machine' => $plan['machine'] ?? '', 'architecture' => $plan['architecture'] ?? '',
            'previous_version' => $plan['previous'] ?? '', 'approved_version' => $plan['version'] ?? '',
        ];
        $result = $this->credentials->ssh($connection['credential'], function (array $ssh) use ($user, $host, $variables): array {
            return $this->scratch->temporary(fn (string $root): array => $this->ansible($root, $user, $host, $ssh, $variables));
        }, ($connection['port'] ?? '') ?: null);
        if (0 !== $result['rc']) {
            throw new \DomainException(self::ERRORS[$result['output']] ?? 'The VM package check failed. Check SSH, Python and package manager access.');
        }
        if ('apply' === $operation) {
            return [];
        }

        $fields = explode("\t", $result['output']);
        if (count($fields) !== ('plan' === $operation ? 5 : 4)
            || !preg_match('/^[a-f0-9]{64}$/D', $fields[0])
            || !preg_match('/^[a-z0-9][a-z0-9+.-]{1,127}$/D', $fields[1])
            || !preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $fields[2])
            || array_filter(array_slice($fields, 3), static fn (string $version): bool => !preg_match('/^[0-9][a-zA-Z0-9.:+~\-]{0,199}$/D', $version))) {
            throw new \DomainException('The worker could not validate package evidence from the VM.');
        }

        [$machine, $name, $architecture, $version] = $fields;

        $evidence = compact('machine', 'name', 'architecture', 'version');
        if ('plan' === $operation) {
            $evidence['previous'] = $version;
            $evidence['version'] = $fields[4];
        }

        return $evidence;
    }

    private function ansible(string $root, string $user, string $host, array $ssh, array $variables): array
    {
        // Use generated inventory and isolated SSH configuration. No imported inventory variables are executable.
        $inventory = ['all' => ['hosts' => [
            'patchrocket_vm' => [
                'ansible_connection' => 'ssh', 'ansible_host' => $host, 'ansible_user' => $user,
                'ansible_shell_executable' => '/bin/sh',
            ],
        ]]];
        $sshArgs = [...$ssh, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no',
            '-o', 'ForwardX11=no', '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no'];
        $inventory['all']['hosts']['patchrocket_vm']['ansible_ssh_args'] = implode(' ', array_map(escapeshellarg(...), $sshArgs));
        $config = "[defaults]\nhost_key_checking = True\nretry_files_enabled = False\nlocal_tmp = $root/tmp\n"
            ."stdout_callback = default\nnocows = True\ndeprecation_warnings = False\n";
        foreach (['inventory.json' => Store::json($inventory), 'vars.json' => Store::json($variables + [
            'result_file' => $root.'/result.json',
        ]), 'ansible.cfg' => $config] as $name => $contents) {
            if (false === file_put_contents($root.'/'.$name, $contents)) {
                throw new \RuntimeException('Could not write the temporary Ansible configuration.');
            }
        }
        $ambient = array_filter(array_keys((array) getenv() + $_ENV + $_SERVER), static fn (string $name): bool => str_starts_with($name, 'ANSIBLE_'));
        $env = [
            'ANSIBLE_CONFIG' => $root.'/ansible.cfg', 'ANSIBLE_HOME' => $root, 'ANSIBLE_NOCOLOR' => '1',
        ] + array_fill_keys($ambient, false);
        $process = new Process(['ansible-playbook', '-i', $root.'/inventory.json', '--extra-vars', '@'.$root.'/vars.json',
            $this->project.'/resources/vm-packages/apt.yml',
        ], $root, $env, input: '', timeout: 'apply' === $variables['operation'] ? 600 : 90);
        $process->disableOutput();
        try {
            $status = $process->run();
        } catch (ProcessTimedOutException) {
            throw new \DomainException('Ansible timed out while waiting for the VM. Check SSH and package manager activity.');
        }
        if (0 !== $status || !is_file($root.'/result.json') || filesize($root.'/result.json') > 4096) {
            throw new \DomainException('Ansible could not complete the VM operation. Check ansible-core, the pinned SSH connection, remote Python and sudo access.');
        }
        $result = json_decode(file_get_contents($root.'/result.json'), true, flags: JSON_THROW_ON_ERROR);
        if (!is_int($result['rc'] ?? null) || !is_string($result['output'] ?? null)) {
            throw new \DomainException('Ansible returned incomplete VM package evidence.');
        }

        return $result;
    }
}
