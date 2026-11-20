<?php
declare(strict_types=1);

namespace App\Secrets;

use App\Discovery\Repository;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class ConnectionCredentials
{
    public function __construct(private readonly SecretManagers $managers, private readonly Repository $scratch)
    {
    }

    public function ssh(string $reference, callable $job, ?string $port = null): mixed
    {
        $bundle = $this->managers->bundle($reference);
        $key = $this->string($bundle, 'private_key');
        $hosts = $this->string($bundle, 'known_hosts');
        if (!str_contains($key, 'PRIVATE KEY-----') || str_contains($hosts, '@revoked')) {
            throw new \DomainException('Provide an SSH private key and its pinned known_hosts entry.');
        }
        $port = filter_var($port ?? $bundle['port'] ?? 22, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        if (false === $port) {
            throw new \DomainException('The managed SSH port is invalid.');
        }

        return $this->scratch->temporary(function (string $root) use ($key, $hosts, $port, $job): mixed {
            $this->write($root.'/identity', rtrim($key)."\n");
            $this->write($root.'/known_hosts', rtrim($hosts)."\n");

            return $job([
                '-F', '/dev/null', '-i', $root.'/identity', '-p', (string) $port,
                '-o', 'UserKnownHostsFile='.$root.'/known_hosts', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'IdentityAgent=none', '-o', 'UpdateHostKeys=no', '-o', 'PasswordAuthentication=no',
                '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey',
            ]);
        });
    }

    public function kubernetes(string $reference, string $context, callable $job): mixed
    {
        $bundle = $this->managers->bundle($reference);

        return $this->scratch->temporary(function (string $root) use ($bundle, $context, $job): mixed {
            $kube = isset($bundle['kubeconfig'])
                ? Yaml::parse($this->string($bundle, 'kubeconfig'), Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE)
                : $this->eksConfig($bundle, $context, $root);
            $this->validateKubeconfig($kube, $context);
            $this->write($root.'/kubeconfig', json_encode($kube, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

            return $job($root.'/kubeconfig');
        });
    }

    private function validateKubeconfig(mixed $config, string $context): void
    {
        if (!is_array($config) || 'Config' !== ($config['kind'] ?? null)
            || !in_array($context, array_column($config['contexts'] ?? [], 'name'), true)) {
            throw new \DomainException('The referenced kubeconfig must include the selected context.');
        }
        foreach ($config['users'] ?? [] as $entry) {
            $user = $entry['user'] ?? [];
            if (!is_array($user) || array_diff(array_keys($user), ['token', 'client-certificate-data', 'client-key-data'])
                || (!isset($user['token']) && !(isset($user['client-certificate-data'], $user['client-key-data'])))) {
                throw new \DomainException('Managed kubeconfig users require an inline token or certificate pair.');
            }
        }
        foreach ($config['clusters'] ?? [] as $entry) {
            $cluster = $entry['cluster'] ?? [];
            $server = $cluster['server'] ?? '';
            $uri = is_string($server) ? parse_url($server) : false;
            if (!$uri || 'https' !== ($uri['scheme'] ?? null) || empty($uri['host'])
                || (!preg_match('/^[a-zA-Z0-9.-]+$/D', $uri['host']) && !filter_var(trim($uri['host'], '[]'), FILTER_VALIDATE_IP))
                || array_diff(array_keys($uri), ['scheme', 'host', 'port', 'path']) || !in_array($uri['path'] ?? '', ['', '/'], true)
                || array_diff(array_keys($cluster), ['server', 'certificate-authority-data', 'tls-server-name'])
                || (isset($cluster['certificate-authority-data']) && !is_string($cluster['certificate-authority-data']))) {
                throw new \DomainException('Managed kubeconfig clusters require HTTPS and may use inline CA data.');
            }
        }
    }

    private function eksConfig(#[\SensitiveParameter] array $bundle, string $context, string $root): array
    {
        $region = $this->string($bundle, 'region');
        $cluster = $this->string($bundle, 'cluster_name');
        if (!preg_match('/^[a-z0-9-]{1,40}$/D', $region) || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$/D', $cluster)) {
            throw new \DomainException('Supply the AWS region and EKS cluster name.');
        }
        $ambient = array_filter(array_keys((array) getenv()), static fn (string $name): bool => str_starts_with($name, 'AWS_'));
        $env = [
            'AWS_ACCESS_KEY_ID' => $this->string($bundle, 'access_key_id'),
            'AWS_SECRET_ACCESS_KEY' => $this->string($bundle, 'secret_access_key'),
            'AWS_SESSION_TOKEN' => $bundle['session_token'] ?? false,
            'AWS_PROFILE' => false, 'AWS_DEFAULT_PROFILE' => false, 'AWS_ROLE_ARN' => false,
            'AWS_WEB_IDENTITY_TOKEN_FILE' => false, 'AWS_ENDPOINT_URL' => false,
            'AWS_CONFIG_FILE' => $root.'/aws-config', 'AWS_SHARED_CREDENTIALS_FILE' => $root.'/aws-credentials',
            'AWS_EC2_METADATA_DISABLED' => 'true',
        ] + array_fill_keys($ambient, false);
        try {
            $job = new Process(['aws', '--no-cli-pager', 'eks', 'get-token', '--region='.$region, '--cluster-name='.$cluster, '--output', 'json'], $root, $env, timeout: 25);
            $data = json_decode($job->mustRun()->getOutput(), true, flags: JSON_THROW_ON_ERROR);
            $token = $this->string($data['status'] ?? [], 'token');
        } catch (\Throwable) {
            throw new \DomainException('Could not obtain an EKS token using the referenced AWS credential.');
        }

        return [
            'apiVersion' => 'v1', 'kind' => 'Config', 'current-context' => $context,
            'contexts' => [['name' => $context, 'context' => ['cluster' => 'target', 'user' => 'worker']]],
            'clusters' => [['name' => 'target', 'cluster' => [
                'server' => $this->string($bundle, 'server'), 'certificate-authority-data' => $this->string($bundle, 'ca_data'),
            ]]],
            'users' => [['name' => 'worker', 'user' => ['token' => $token]]],
        ];
    }

    private function string(#[\SensitiveParameter] array $bundle, string $field): string
    {
        $value = $bundle[$field] ?? null;
        if (!is_string($value) || '' === trim($value)) {
            throw new \DomainException('The managed credential bundle is missing '.$field.'.');
        }

        return $value;
    }

    private function write(string $path, #[\SensitiveParameter] string $content): void
    {
        if (false === file_put_contents($path, $content) || !chmod($path, 0600)) {
            throw new \RuntimeException('Could not prepare a temporary credential.');
        }
    }
}
