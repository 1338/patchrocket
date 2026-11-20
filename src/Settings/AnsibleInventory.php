<?php
declare(strict_types=1);

namespace App\Settings;

use App\Secrets\SecretManagers;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

final class AnsibleInventory
{
    public const MAX_UPLOAD = 524288;
    private const VARIABLES = ['ansible_host', 'ansible_user', 'ansible_port', 'ansible_connection', 'patchrocket_credential'];

    public function read(#[\SensitiveParameter] string $contents, string $sshUser, string $credential, string $group): array
    {
        if (strlen($contents) > self::MAX_UPLOAD) {
            throw new \DomainException('Upload an Ansible inventory of 512 KiB or less.');
        }
        if ('' !== $sshUser && !preg_match('/^[a-zA-Z_][a-zA-Z0-9_.-]*$/D', $sshUser)) {
            throw new \DomainException('Enter a valid default SSH user.');
        }
        if ('' !== $credential && !SecretManagers::validReference($credential)) {
            throw new \DomainException('Use a default credential reference in manager:secret format.');
        }
        try {
            $inventory = Yaml::parse($contents, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE, maxNestingLevel: 24);
        } catch (ParseException) {
            $inventory = null;
        }
        if (!is_array($inventory) || array_is_list($inventory) || isset($inventory['plugin'])) {
            throw new \DomainException('Upload static Ansible YAML or a JSON export from ansible-inventory --list.');
        }
        $hosts = array_key_exists('_meta', $inventory)
            ? $this->exportedHosts($inventory)
            : $this->staticHosts($inventory);
        if (count($hosts) > 1000) {
            throw new \DomainException('Split this export into inventories of up to 1,000 hosts.');
        }
        $rows = [];
        $matched = $skipped = 0;
        foreach ($hosts as $name => $host) {
            $groups = array_map('strval', array_keys($host['groups']));
            if ('' !== $group && !in_array($group, $groups, true)) {
                continue;
            }
            ++$matched;
            $vars = array_replace($host['vars'], $host['hostvars']);
            if (!empty($host['ambiguous']) || array_diff_key($host['conflicts'] ?? [], $host['hostvars'])) {
                ++$skipped;
                continue;
            }
            $address = $vars['ansible_host'] ?? $name;
            $user = $vars['ansible_user'] ?? $sshUser;
            $connection = $vars['ansible_connection'] ?? 'ssh';
            $port = $vars['ansible_port'] ?? '';
            if (!is_string($address) || !is_string($user) || false === $port
                || ('' !== $port && ((!is_int($port) && !is_string($port))
                    || false === filter_var($port, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]])))
                || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}$/D', (string) $name)
                || !Connections::validVmTarget($user.'@'.$address)
                || !in_array($connection, ['ssh', 'ansible.builtin.ssh', 'smart', 'paramiko', 'paramiko_ssh'], true)
                || in_array(strtolower($address), ['localhost', '127.0.0.1', '::1'], true)) {
                ++$skipped;
                continue;
            }
            $reference = $vars['patchrocket_credential'] ?? $credential;
            $rows[] = [
                'name' => (string) $name, 'target' => $user.'@'.$address, 'port' => (string) $port,
                'credential' => is_string($reference) && SecretManagers::validReference($reference) ? $reference : '',
                'groups' => array_values(array_diff($groups, ['all'])),
            ];
        }
        if (!$matched) {
            throw new \DomainException('The inventory contains no hosts in the selected group.');
        }

        return ['hosts' => $rows, 'skipped' => $skipped];
    }

    private function staticHosts(array $inventory): array
    {
        $hosts = [];
        $defaults = $this->variables($inventory['all']['vars'] ?? []);
        foreach ($inventory as $name => $group) {
            if (is_array($group)) {
                $this->staticGroup($hosts, $group, 'all' === $name ? ['all'] : ['all', (string) $name], $defaults);
            }
        }

        return $hosts;
    }

    private function staticGroup(array &$hosts, array $group, array $path, array $inherited): void
    {
        $vars = array_replace($inherited, $this->variables($group['vars'] ?? []));
        foreach ((array) ($group['hosts'] ?? []) as $name => $entry) {
            if (null !== $entry && !is_array($entry)) {
                continue;
            }
            $host = $hosts[$name] ?? ['vars' => [], 'hostvars' => [], 'groups' => []];
            foreach ($vars as $key => $value) {
                if (array_key_exists($key, $host['vars']) && $host['vars'][$key] !== $value) {
                    $host['conflicts'][$key] = true;
                }
            }
            foreach ($this->variables($entry) as $key => $value) {
                if (array_key_exists($key, $host['hostvars']) && $host['hostvars'][$key] !== $value) {
                    $host['ambiguous'] = true;
                }
                $host['hostvars'][$key] = $value;
            }
            $host['vars'] += $vars;
            $host['groups'] += array_fill_keys($path, true);
            $hosts[$name] = $host;
        }
        foreach ((array) ($group['children'] ?? []) as $name => $child) {
            if (is_array($child)) {
                $this->staticGroup($hosts, $child, [...$path, (string) $name], $vars);
            }
        }
    }

    private function exportedHosts(array $inventory): array
    {
        $hosts = [];
        $hostvars = (array) ($inventory['_meta']['hostvars'] ?? []);
        unset($inventory['_meta']);
        if (count($inventory) > 256) {
            throw new \DomainException('Split this Ansible export into inventories of up to 256 groups.');
        }
        foreach ($inventory as $name => $group) {
            if (!is_array($group)) {
                continue;
            }
            $pending = [(string) $name];
            $visited = [];
            while ($pending) {
                $child = array_pop($pending);
                if (isset($visited[$child]) || !isset($inventory[$child])) {
                    continue;
                }
                $visited[$child] = true;
                foreach ((array) ($inventory[$child]['hosts'] ?? []) as $host) {
                    if (is_string($host)) {
                        $hosts[$host] ??= ['vars' => [], 'hostvars' => $this->variables($hostvars[$host] ?? []), 'groups' => []];
                        $hosts[$host]['groups'][$name] = true;
                    }
                }
                foreach ((array) ($inventory[$child]['children'] ?? []) as $nested) {
                    if (is_string($nested)) {
                        $pending[] = $nested;
                    }
                }
            }
        }

        return $hosts;
    }

    private function variables(mixed $vars): array
    {
        return is_array($vars) ? array_intersect_key($vars, array_flip(self::VARIABLES)) : [];
    }
}
