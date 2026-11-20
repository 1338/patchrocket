<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Audit\Store;
use App\Secrets\SecretManagers;
use Symfony\Component\Process\Process;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class CloudDeliveryDiscovery
{
    private const UUID = '/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/iD';
    private const MAX_RESPONSE = 4194304;

    public function __construct(
        private readonly SecretManagers $secrets,
        private readonly Repository $scratch,
        private readonly HttpClientInterface $http,
    ) {
    }

    public function discover(string $provider, string $scope, string $region, string $credential, ?callable $warning = null): array
    {
        $scope = trim($scope);
        $region = trim($region);
        $valid = match ($provider) {
            'azure' => preg_match(self::UUID, $scope),
            'aws' => preg_match('/^[0-9]{12}$/D', $scope) && preg_match('/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/D', $region),
            'gcp' => preg_match('/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/D', $scope),
            default => false,
        };
        if (!$valid) {
            throw new \DomainException('Enter an Azure subscription ID, an AWS account ID and region, or a Google Cloud project ID.');
        }
        $bundle = '' === $credential ? null : $this->secrets->bundle($credential);
        return $this->scratch->temporary(function (string $root) use ($provider, $scope, $region, $bundle, $warning): array {
            $groups = match ($provider) {
                'azure' => $this->azure(strtolower($scope), $bundle),
                'aws' => $this->aws($scope, $region, $bundle, $root),
                'gcp' => $this->gcp($scope, $bundle, $root),
            };

            return $this->collect($groups, $warning);
        });
    }

    private function collect(array $groups, ?callable $warning): array
    {
        $completed = 0;
        $candidates = [];
        foreach ($groups as $name => $read) {
            try {
                array_push($candidates, ...$read());
                ++$completed;
            } catch (\DomainException) {
                if (null !== $warning) {
                    $warning('Could not list '.$name.'. Check cloud permissions and worker tooling.');
                }
            }
        }
        if (0 === $completed) {
            throw new \DomainException('Cloud discovery could not read any configured resource types.');
        }

        return $candidates;
    }

    private function azure(string $subscription, #[\SensitiveParameter] ?array $bundle): array
    {
        if (null === $bundle) {
            $auth = $this->command(['az', 'account', 'get-access-token', '--subscription='.$subscription,
                '--resource=https://management.azure.com/', '--only-show-errors', '--output=json']);
            $token = $this->credential($auth, 'accessToken');
        } else {
            $tenant = $this->credential($bundle, 'tenant_id');
            $client = $this->credential($bundle, 'client_id');
            if (!preg_match(self::UUID, $tenant) || !preg_match(self::UUID, $client)) {
                throw new \DomainException('Azure credentials need a tenant ID and application client ID.');
            }
            $auth = $this->request('POST', 'https://login.microsoftonline.com/'.$tenant.'/oauth2/v2.0/token', [
                'body' => [
                    'client_id' => $client, 'client_secret' => $this->credential($bundle, 'client_secret'),
                    'grant_type' => 'client_credentials', 'scope' => 'https://management.azure.com/.default',
                ],
            ]);
            $token = $this->credential($auth, 'access_token');
        }
        $base = '/subscriptions/'.$subscription.'/providers/';

        return [
            'Azure container registries' => function () use ($base, $token): array {
                $result = [];
                foreach ($this->azureList($base.'Microsoft.ContainerRegistry/registries', '2023-07-01', $token) as $item) {
                    $this->candidate($result, 'registry', $item['properties']['loginServer'] ?? '', (string) ($item['name'] ?? '').' · Azure Container Registry', $item['id'] ?? '');
                }
                return $result;
            },
            'Azure Kubernetes clusters' => function () use ($base, $token): array {
                $result = [];
                foreach ($this->azureList($base.'Microsoft.ContainerService/managedClusters', '2024-05-01', $token) as $item) {
                    $name = $item['name'] ?? '';
                    $address = $item['properties']['privateFQDN'] ?? $item['properties']['fqdn'] ?? $name;
                    $this->candidate($result, 'cluster', $address, $name.' · AKS', $item['id'] ?? '');
                }
                return $result;
            },
            'Azure virtual machines' => function () use ($base, $token): array {
                $result = [];
                foreach ($this->azureList($base.'Microsoft.Compute/virtualMachines', '2024-07-01', $token) as $item) {
                    $name = $item['name'] ?? '';
                    $address = $item['properties']['osProfile']['computerName'] ?? $name;
                    $this->machine($result, $name, $address, 'Azure VM', $item['id'] ?? '', $item['tags'] ?? []);
                }
                return $result;
            },
        ];
    }

    private function azureList(string $path, string $version, #[\SensitiveParameter] string $token): array
    {
        $url = 'https://management.azure.com'.$path.'?api-version='.$version;
        $items = [];
        for ($page = 0; $page < 15; ++$page) {
            $result = $this->request('GET', $url, ['auth_bearer' => $token]);
            if (!is_array($result['value'] ?? null)) {
                throw new \DomainException('Azure returned an unexpected resource list.');
            }
            array_push($items, ...$result['value']);
            $url = $result['nextLink'] ?? '';
            if ('' === $url) {
                return $items;
            }
            $parts = is_string($url) ? parse_url($url) : false;
            if (!$parts || 'https' !== ($parts['scheme'] ?? null) || 'management.azure.com' !== ($parts['host'] ?? null)
                || $path !== ($parts['path'] ?? null) || array_diff(array_keys($parts), ['scheme', 'host', 'path', 'query'])) {
                throw new \DomainException('Azure returned an unexpected pagination link.');
            }
        }

        throw new \DomainException('Azure inventory exceeded the discovery page limit.');
    }

    private function aws(string $account, string $region, #[\SensitiveParameter] ?array $bundle, string $root): array
    {
        $env = [];
        if (null !== $bundle) {
            $env = $this->clearEnvironment('AWS_');
            $env['AWS_ACCESS_KEY_ID'] = $this->credential($bundle, 'access_key_id');
            $env['AWS_SECRET_ACCESS_KEY'] = $this->credential($bundle, 'secret_access_key');
            $env['AWS_SESSION_TOKEN'] = isset($bundle['session_token']) ? $this->credential($bundle, 'session_token') : false;
            $env['AWS_EC2_METADATA_DISABLED'] = 'true';
            $env['AWS_CONFIG_FILE'] = $root.'/config';
            $env['AWS_SHARED_CREDENTIALS_FILE'] = $root.'/credentials';
        }
        $aws = fn (array $args): array => $this->command(['aws', '--no-cli-pager', '--region='.$region, '--output=json', ...$args], $env);
        if (($aws(['sts', 'get-caller-identity'])['Account'] ?? null) !== $account) {
            throw new \DomainException('The AWS identity does not match the selected account.');
        }

        return [
            'AWS container registries' => function () use ($aws, $account): array {
                $result = [];
                foreach ($aws(['ecr', 'describe-repositories', '--registry-id='.$account])['repositories'] ?? [] as $item) {
                    $uri = $item['repositoryUri'] ?? '';
                    $host = explode('/', $uri, 2)[0];
                    $this->candidate($result, 'registry', $host, 'Amazon ECR · '.$host, $host);
                }
                return $result;
            },
            'AWS Kubernetes clusters' => function () use ($aws, $account, $region): array {
                $result = [];
                foreach ($aws(['eks', 'list-clusters'])['clusters'] ?? [] as $name) {
                    $this->candidate($result, 'cluster', $name, $name.' · Amazon EKS', $account.'/'.$region.'/'.$name);
                }
                return $result;
            },
            'AWS virtual machines' => function () use ($aws): array {
                $result = [];
                foreach ($aws(['ec2', 'describe-instances'])['Reservations'] ?? [] as $reservation) {
                    foreach ($reservation['Instances'] ?? [] as $instance) {
                        $tags = array_column($instance['Tags'] ?? [], 'Value', 'Key');
                        $id = $instance['InstanceId'] ?? '';
                        $address = ($instance['PublicDnsName'] ?? '') ?: (($instance['PrivateDnsName'] ?? '') ?: ($instance['PrivateIpAddress'] ?? $id));
                        $this->machine($result, $tags['Name'] ?? $id, $address, 'Amazon EC2', $id, $tags);
                    }
                }
                return $result;
            },
        ];
    }

    private function gcp(string $project, #[\SensitiveParameter] ?array $bundle, string $root): array
    {
        $env = [];
        if (null !== $bundle) {
            $account = $bundle['service_account'] ?? $bundle;
            if (!is_array($account)) {
                throw new \DomainException('Provide a Google Cloud service account credential object.');
            }
            $key = $this->credential($account, 'private_key');
            $email = $this->credential($account, 'client_email');
            if (($account['type'] ?? null) !== 'service_account' || !str_starts_with($key, '-----BEGIN PRIVATE KEY-----')
                || !preg_match('/^[a-z0-9_.-]+@[a-z0-9.-]+\.gserviceaccount\.com$/iD', $email)) {
                throw new \DomainException('Provide a Google Cloud service account key.');
            }
            $file = $root.'/service-account.json';
            $auth = [
                'type' => 'service_account', 'client_email' => $email, 'private_key' => $key,
                'token_uri' => 'https://oauth2.googleapis.com/token',
            ];
            if (isset($account['private_key_id'])) {
                $auth['private_key_id'] = $this->credential($account, 'private_key_id');
            }
            if (false === file_put_contents($file, Store::json($auth)) || !chmod($file, 0600)) {
                throw new \DomainException('Could not prepare the Google Cloud credential.');
            }
            $env = $this->clearEnvironment('CLOUDSDK_');
            $env['CLOUDSDK_CONFIG'] = $root;
            $env['CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE'] = $file;
        }
        $gcloud = fn (array $args): array => $this->command(['gcloud', ...$args, '--project='.$project, '--quiet', '--format=json'], $env);

        return [
            'Google Artifact Registry repositories' => function () use ($gcloud): array {
                $result = [];
                foreach ($gcloud(['artifacts', 'repositories', 'list', '--location=all']) as $item) {
                    if ('DOCKER' === ($item['format'] ?? null)
                        && preg_match('~^projects/[^/]+/locations/([a-z0-9-]+)/repositories/[^/]+$~D', $item['name'] ?? '', $parts)) {
                        $host = $parts[1].'-docker.pkg.dev';
                        $this->candidate($result, 'registry', $host, 'Google Artifact Registry · '.$parts[1], $host);
                    }
                }
                return $result;
            },
            'Google Kubernetes clusters' => function () use ($gcloud, $project): array {
                $result = [];
                foreach ($gcloud(['container', 'clusters', 'list']) as $item) {
                    $name = $item['name'] ?? '';
                    $this->candidate($result, 'cluster', $item['endpoint'] ?? $name, $name.' · GKE',
                        $project.'/'.($item['location'] ?? '').'/'.$name);
                }
                return $result;
            },
            'Google Compute Engine instances' => function () use ($gcloud): array {
                $result = [];
                foreach ($gcloud(['compute', 'instances', 'list']) as $item) {
                    $name = $item['name'] ?? '';
                    $interface = $item['networkInterfaces'][0] ?? [];
                    $address = $interface['accessConfigs'][0]['natIP'] ?? $interface['networkIP'] ?? $name;
                    $this->machine($result, $name, $address, 'Compute Engine', $item['selfLink'] ?? $name, $item['labels'] ?? []);
                }
                return $result;
            },
        ];
    }

    private function machine(array &$result, string $name, string $address, string $provider, string $id, array $tags): void
    {
        $this->candidate($result, 'vm', $address, $name.' · '.$provider, $id);
        $tags = array_change_key_case($tags, CASE_LOWER);
        $hint = implode(' ', [$name, $tags['service'] ?? '', $tags['application'] ?? '', $tags['app.kubernetes.io/name'] ?? '', $tags['patchrocket-service'] ?? '']);
        $endpoint = $tags['patchrocket-endpoint'] ?? $tags['patchrocket_endpoint'] ?? '';
        if (is_string($endpoint) && preg_match('~^https?://~i', $endpoint)) {
            foreach (['harbor' => 'harbor', 'jenkins' => 'jenkins', 'argocd' => 'argo[-_ ]?cd'] as $kind => $pattern) {
                if (preg_match('~(?:^|[^a-z0-9])'.$pattern.'(?:$|[^a-z0-9])~i', $hint)) {
                    $this->candidate($result, $kind, $endpoint, $name.' · '.$provider.' metadata', $id);
                }
            }
        }
    }

    private function candidate(array &$result, string $kind, string $endpoint, string $label, string $id): void
    {
        if ('' !== $endpoint) {
            $result[] = ['kind' => $kind, 'endpoint' => $endpoint, 'label' => $label, 'resource_id' => $id];
        }
    }

    private function credential(#[\SensitiveParameter] array $bundle, string $field): string
    {
        $value = $bundle[$field] ?? null;
        if (!is_string($value) || '' === trim($value) || strlen($value) > 65536) {
            throw new \DomainException('The cloud credential bundle is missing '.$field.'.');
        }

        return $value;
    }

    private function clearEnvironment(string $prefix): array
    {
        return array_fill_keys(array_filter(array_keys((array) getenv() + $_ENV + $_SERVER),
            static fn (string $name): bool => str_starts_with($name, $prefix)), false);
    }

    private function command(array $command, #[\SensitiveParameter] array $env = []): array
    {
        $process = new Process($command, env: $env, timeout: 22);
        try {
            $size = 0;
            $process->mustRun(static function (string $type, string $chunk) use (&$size): void {
                $size += strlen($chunk);
                if ($size > self::MAX_RESPONSE) {
                    throw new \DomainException('Cloud response exceeded the discovery limit.');
                }
            });
            $data = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
            if (is_array($data)) {
                return $data;
            }
        } catch (\Throwable) {
            // Cloud tools can include credential or request details in their diagnostics.
        }
        throw new \DomainException('The cloud CLI did not return a usable response.');
    }

    private function request(string $method, string $url, #[\SensitiveParameter] array $options): array
    {
        try {
            return $this->http->request($method, $url, $options + [
                'max_redirects' => 0, 'timeout' => 10, 'max_duration' => 20, 'extra' => ['trace_content' => false],
                'on_progress' => static function (int $downloaded): void {
                    if ($downloaded > self::MAX_RESPONSE) {
                        throw new \RuntimeException('Cloud response exceeded the discovery limit.');
                    }
                },
            ])->toArray();
        } catch (\Throwable) {
            throw new \DomainException('The Azure API did not return a usable response.');
        }
    }
}
