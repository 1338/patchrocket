<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\DeliveryDiscovery;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\MessageBus;

final class DeliveryDiscoveryTest extends TestCase
{
    public function testRecognizedHostServicesKeepDistinctEndpoints(): void
    {
        $observed = ConnectionDeliveryDiscovery::fromHost('worker.example.test', [
            ['service', 'jenkins.service'],
            ['docker', 'jenkins-blue', 'jenkins/jenkins:lts', '0.0.0.0:8443->8443/tcp, :::8443->8443/tcp, 0.0.0.0:50000->50000/tcp'],
            ['docker', 'jenkins-green', 'jenkins/jenkins:lts', '0.0.0.0:8080->8080/tcp, 127.0.0.1:9000->9000/tcp'],
            ['docker', 'distribution', 'registry:2.8', '0.0.0.0:5000->5000/tcp'],
            ['docker', 'harbor-db', 'goharbor/harbor-db:v2.12', '5432/tcp'],
        ]);
        self::assertSame([
            'https://worker.example.test:8443',
            'http://worker.example.test:8080',
            'http://worker.example.test:5000',
        ], array_column($observed, 'endpoint'));
    }

    public function testKubernetesPrefersTheIngressAndFindsArgoApplicationNamespaces(): void
    {
        $observed = ConnectionDeliveryDiscovery::fromKubernetes([
            'services' => [
                ['metadata' => ['name' => 'jenkins-web', 'namespace' => 'build']],
                ['metadata' => ['name' => 'jenkins-agent', 'namespace' => 'build', 'labels' => ['app.kubernetes.io/name' => 'jenkins']]],
            ],
            'ingresses.networking.k8s.io' => [[
                'metadata' => ['name' => 'shared-proxy', 'namespace' => 'build'],
                'spec' => [
                    'tls' => [['hosts' => ['ci.example.test']]],
                    'rules' => [['host' => 'ci.example.test', 'http' => ['paths' => [
                        ['path' => '/jenkins', 'backend' => ['service' => ['name' => 'jenkins-web']]],
                    ]]]],
                ],
            ]],
            'applications.argoproj.io' => [
                ['metadata' => ['namespace' => 'argocd-blue', 'name' => 'app-one']],
                ['metadata' => ['namespace' => 'argocd-blue', 'name' => 'app-two']],
                ['metadata' => ['namespace' => 'argocd-green', 'name' => 'app-three']],
            ],
        ], 'west', 'connection-id');
        self::assertSame(['jenkins', 'argocd', 'argocd'], array_column($observed, 'kind'));
        self::assertSame(['https://ci.example.test/jenkins', 'argocd-blue.svc', 'argocd-green.svc'], array_column($observed, 'endpoint'));
        self::assertSame(['build', 'argocd-blue', 'argocd-green'], array_column($observed, 'namespace'));
    }

    public function testHybridCandidatesMergeEvidenceWithoutLosingOtherInstances(): void
    {
        [, , , $discovery] = $this->services();
        self::assertSame(1, $discovery->record('SSH scope', [
            ['kind' => 'jenkins', 'endpoint' => 'https://CI.EXAMPLE.TEST:443/jenkins/'],
            ['kind' => 'jenkins', 'endpoint' => 'https://someone:secret@ci.example.test/jenkins'],
        ]));
        self::assertSame(2, $discovery->record('Azure scope', [
            ['kind' => 'jenkins', 'endpoint' => 'https://ci.example.test/jenkins'],
            ['kind' => 'jenkins', 'endpoint' => 'https://ci.example.test/other'],
        ]));
        $candidates = array_values($discovery->all());
        self::assertCount(2, $candidates);
        self::assertSame('https://ci.example.test/jenkins', $candidates[0]['endpoint']);
        self::assertEqualsCanonicalizing(['SSH scope', 'Azure scope'], array_keys($candidates[0]['sources']));
        $discovery->record('SSH scope', []);
        self::assertCount(2, $discovery->all());
        self::assertSame(['Azure scope'], array_keys(array_values($discovery->all())[0]['sources']));
    }

    public function testAdoptingDoesNotReplaceAnExistingArgoNamespace(): void
    {
        [$connections, $jenkins, $operator, $discovery] = $this->services();
        $clusterId = $connections->save('cluster', ['name' => 'West', 'target' => 'west', 'credential' => 'vault:kubeconfig']);
        $connections->saveArgo($clusterId, 'argocd-blue', 'vault:blue');
        $discovery->record('west', [
            ['kind' => 'argocd', 'endpoint' => 'argocd-green.svc', 'namespace' => 'argocd-green', 'connection_id' => $clusterId],
            ['kind' => 'jenkins', 'endpoint' => 'https://ci.example.test/jenkins'],
            ['kind' => 'harbor', 'endpoint' => 'harbor.example.test:5000'],
        ]);
        $ids = array_column($discovery->all(), 'id', 'kind');
        $data = ['cluster' => $clusterId, 'namespace' => 'argocd-green'];
        $discovery->adopt($ids['argocd'], $data + ['reference' => 'vault:green']);
        $discovery->adopt($ids['argocd'], $data);
        $discovery->adopt($ids['jenkins'], ['endpoint' => 'https://ci.example.test/jenkins', 'reference' => 'vault:jenkins']);
        $discovery->adopt($ids['harbor'], ['endpoint' => 'harbor.example.test:5000', 'reference' => 'vault:harbor']);
        self::assertCount(2, $connections->all());
        $green = $discovery->all()[$ids['argocd']]['binding']['connection_id'];
        self::assertNotSame($clusterId, $green);
        self::assertSame('argocd-blue', $connections->get($clusterId)['data']['argo_namespace']);
        self::assertSame('argocd-green', $connections->get($green)['data']['argo_namespace']);
        self::assertSame('vault:green', $connections->get($green)['data']['argo_credential']);
        self::assertSame('vault:jenkins', $jenkins->referenceFor('https://ci.example.test/jenkins/job/main'));
        self::assertSame('vault:harbor', $operator->registryReference('harbor.example.test:5000'));
    }

    private function services(): array
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $connections = new Connections($store, new MessageBus());
        $jenkins = new JenkinsConnections($store);
        $operator = new OperatorSettings($store);

        return [$connections, $jenkins, $operator, new DeliveryDiscovery($store, $connections, $jenkins, $operator)];
    }
}
