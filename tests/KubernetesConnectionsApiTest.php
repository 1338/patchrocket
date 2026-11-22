<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Controller\KubernetesConnectionsApi;
use App\Discovery\Repository;
use App\Secrets\AnsibleVault;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\KubernetesChecks;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class KubernetesConnectionsApiTest extends TestCase
{
    public function testSavingRequiresTheSameScopeAndActorThatPassedTheWorkerTest(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $bus = new MessageBus();
        $connections = new Connections($store, $bus);
        $checks = new KubernetesChecks($store, $bus);
        $managers = new SecretManagers($store, new AnsibleVault(new Repository(new Inventory($store))));
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);
        $controller = new KubernetesConnectionsApi($store, $connections, $managers, $checks, $csrf);
        $selection = [
            'credentialMode' => 'managed', 'credential' => 'vault:cluster',
            'target' => 'test-context', 'namespaceMode' => 'selected', 'namespaces' => ['staging'],
        ];
        $payload = ['name' => 'Test cluster'] + $selection;
        self::assertSame(422, $controller->save($this->request($payload))->getStatusCode());

        $checkId = $checks->queue('tester', 'test', $selection);
        $row = $checks->get($checkId);
        self::assertTrue($checks->update($checkId, $row, array_replace($row, [
            'status' => 'complete', 'result' => ['passed' => true, 'endpoint' => 'https://kube.example.test'],
        ])));
        $proof = json_decode($controller->check($this->request([]), $checkId)->getContent(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($row['expires'], $proof['expiresAt']);
        $payload['checkId'] = $checkId;
        self::assertSame(422, $controller->save($this->request($payload, 'other-admin'))->getStatusCode());
        self::assertSame(422, $controller->save($this->request(array_replace($payload, ['namespaces' => ['production']])))->getStatusCode());

        $saved = $controller->save($this->request($payload));
        self::assertSame(201, $saved->getStatusCode());
        $id = json_decode($saved->getContent(), true, flags: JSON_THROW_ON_ERROR)['id'];
        self::assertSame(['staging'], Connections::clusterNamespaces($connections->get($id)['data']));
        self::assertSame('https://kube.example.test', $connections->get($id)['data']['test_endpoint']);
    }

    private function request(array $data, string $actor = 'tester'): Request
    {
        $request = Request::create('/api/kubernetes/connections', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: json_encode($data, JSON_THROW_ON_ERROR));
        $request->attributes->set('_dashboard_actor', $actor);

        return $request;
    }
}
