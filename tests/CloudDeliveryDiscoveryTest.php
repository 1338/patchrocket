<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\CloudDeliveryDiscovery;
use App\Discovery\Repository;
use App\Secrets\AnsibleVault;
use App\Secrets\SecretManagers;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;

final class CloudDeliveryDiscoveryTest extends TestCase
{
    public function testAzureReadsNativeResourcesAndKeepsPartialResults(): void
    {
        $scope = '00000000-0000-0000-0000-000000000001';
        $tokenUrl = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000002/oauth2/v2.0/token';
        $api = 'https://management.azure.com/subscriptions/'.$scope.'/providers/';
        $http = new MockHttpClient(static function (string $method, string $url, array $options) use ($tokenUrl, $api): JsonMockResponse {
            self::assertSame(0, $options['max_redirects']);
            if ($url === $tokenUrl) {
                self::assertSame('POST', $method);
                self::assertStringContainsString('grant_type=client_credentials', $options['body']);

                return new JsonMockResponse(['access_token' => 'azure-fixture-access']);
            }
            self::assertSame('GET', $method);
            self::assertStringStartsWith($api, $url);
            if (str_contains($url, 'registries')) {
                $name = str_contains($url, 'page=2') ? 'east' : 'west';
                $result = ['value' => [['name' => $name, 'id' => '/registries/'.$name, 'properties' => ['loginServer' => $name.'.azurecr.io']]]];
                if ('west' === $name) {
                    $result['nextLink'] = $api.'Microsoft.ContainerRegistry/registries?api-version=2023-07-01&page=2';
                }

                return new JsonMockResponse($result);
            }
            if (str_contains($url, 'managedClusters')) {
                return new JsonMockResponse(['value' => [
                    ['name' => 'private-aks', 'id' => '/clusters/private-aks', 'properties' => ['privateFQDN' => 'private.k8s.example']],
                ]]);
            }

            return new JsonMockResponse(['error' => 'fixture permissions'], ['http_code' => 403]);
        });
        $this->withDiscovery($http, [
            'tenant_id' => '00000000-0000-0000-0000-000000000002',
            'client_id' => '00000000-0000-0000-0000-000000000003',
            'client_secret' => 'synthetic',
        ], static function (CloudDeliveryDiscovery $discovery) use ($scope): void {
            $warnings = [];
            $candidates = $discovery->discover('azure', $scope, '', 'fixture:cloud', static function (string $message) use (&$warnings): void {
                $warnings[] = $message;
            });
            self::assertSame(['west.azurecr.io', 'east.azurecr.io', 'private.k8s.example'], array_column($candidates, 'endpoint'));
            self::assertSame('cluster', $candidates[2]['kind']);
            self::assertStringContainsString('virtual machines', $warnings[0]);
        });
    }

    public function testAwsChecksAccountAndRecognizesExplicitJenkinsMetadata(): void
    {
        $this->withDiscovery(new MockHttpClient(), ['access_key_id' => 'test-id', 'secret_access_key' => 'test-key'],
            static function (CloudDeliveryDiscovery $discovery): void {
                $candidates = $discovery->discover('aws', '012345678901', 'eu-west-1', 'fixture:cloud');
                self::assertSame(['registry', 'cluster', 'vm', 'jenkins'], array_column($candidates, 'kind'));
                self::assertSame(['012345678901.dkr.ecr.eu-west-1.amazonaws.com', 'cluster-alpha', '10.0.0.10',
                    'https://ci.example.com/jenkins'], array_column($candidates, 'endpoint'));
                try {
                    $discovery->discover('aws', '012345678902', 'eu-west-1', 'fixture:cloud');
                    self::fail('Discovery must use the selected AWS account.');
                } catch (DomainException $error) {
                    self::assertStringContainsString('selected account', $error->getMessage());
                }
            });
    }

    public function testGoogleUsesAnIsolatedServiceAccountAndDockerRegistries(): void
    {
        $this->withDiscovery(new MockHttpClient(), ['service_account' => [
            'type' => 'service_account', 'client_email' => 'test@fixture.iam.gserviceaccount.com',
            'private_key' => "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
        ]], static function (CloudDeliveryDiscovery $discovery): void {
            $candidates = $discovery->discover('gcp', 'fixture-project', '', 'fixture:cloud');
            self::assertSame(['registry', 'cluster', 'vm', 'harbor'], array_column($candidates, 'kind'));
            self::assertSame(['us-west1-docker.pkg.dev', '10.0.0.11', '10.0.0.12', 'https://registry.example.com'],
                array_column($candidates, 'endpoint'));
        });
    }

    private function withDiscovery(MockHttpClient $http, array $bundle, callable $test): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $scratch = new Repository(new Inventory($store));
        $secrets = new SecretManagers($store, new AnsibleVault($scratch));
        $secrets->save('fixture', 'vault', 'kv');
        $scratch->temporary(static function (string $root) use ($secrets, $scratch, $http, $test, $bundle): void {
            $scripts = [
                'vault' => <<<'SH'
#!/bin/sh
printf '%s' "$CLOUD_FIXTURE_BUNDLE"
SH,
                'aws' => <<<'SH'
#!/bin/sh
set -eu
test "$2" = --region=eu-west-1
test "$AWS_ACCESS_KEY_ID" = test-id && test "$AWS_SECRET_ACCESS_KEY" = test-key
test "$AWS_EC2_METADATA_DISABLED" = true && test -z "${AWS_ENDPOINT_URL:-}"
case "$4 $5" in
  'sts get-caller-identity') printf '%s' '{"Account":"012345678901"}' ;;
  'ecr describe-repositories') printf '%s' '{"repositories":[{"repositoryUri":"012345678901.dkr.ecr.eu-west-1.amazonaws.com/demo"}]}' ;;
  'eks list-clusters') printf '%s' '{"clusters":["cluster-alpha"]}' ;;
  'ec2 describe-instances') printf '%s' '{"Reservations":[{"Instances":[{"InstanceId":"i-fixture","PrivateIpAddress":"10.0.0.10","Tags":[{"Key":"Name","Value":"jenkins-one"},{"Key":"patchrocket-endpoint","Value":"https://ci.example.com/jenkins"}]}]}]}' ;;
  *) exit 2 ;;
esac
SH,
                'gcloud' => <<<'SH'
#!/bin/sh
set -eu
test -r "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"
test "$(stat -c '%a' "$CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")" = 600
test -z "${CLOUDSDK_CORE_ACCOUNT:-}"
case "$1 $2 $3" in
  'artifacts repositories list') printf '%s' '[{"name":"projects/fixture-project/locations/us-west1/repositories/app","format":"DOCKER"},{"name":"projects/fixture-project/locations/us-west1/repositories/pkg","format":"MAVEN"}]' ;;
  'container clusters list') printf '%s' '[{"name":"gke","endpoint":"10.0.0.11","location":"us-west1"}]' ;;
  'compute instances list') printf '%s' '[{"name":"harbor-main","networkInterfaces":[{"networkIP":"10.0.0.12"}],"labels":{"patchrocket-endpoint":"https://registry.example.com"}}]' ;;
  *) exit 2 ;;
esac
SH,
            ];
            foreach ($scripts as $name => $contents) {
                file_put_contents($root.'/'.$name, $contents);
                chmod($root.'/'.$name, 0700);
            }
            $before = $_ENV;
            $path = getenv('PATH');
            $_ENV['PATH'] = $root.':'.getenv('PATH');
            putenv('PATH='.$_ENV['PATH']);
            $_ENV['CLOUD_FIXTURE_BUNDLE'] = Store::json($bundle);
            $_ENV['AWS_ENDPOINT_URL'] = 'http://unwanted.example';
            $_ENV['CLOUDSDK_CORE_ACCOUNT'] = 'unwanted@example';
            try {
                $test(new CloudDeliveryDiscovery($secrets, $scratch, $http));
            } finally {
                $_ENV = $before;
                putenv(false === $path ? 'PATH' : 'PATH='.$path);
            }
        });
    }
}
