<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Settings\KubernetesChecks;
use App\Settings\RunKubernetesCheck;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;

final class KubernetesChecksTest extends TestCase
{
    public function testCheckIsClaimedOnlyOnce(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $dispatched = null;
        $bus = $this->createMock(MessageBusInterface::class);
        $bus->expects(self::once())->method('dispatch')->willReturnCallback(static function (RunKubernetesCheck $check) use (&$dispatched): Envelope {
            $dispatched = $check->id;

            return new Envelope($check);
        });
        $checks = new KubernetesChecks($store, $bus);
        $id = $checks->queue('admin', 'contexts', ['credentialMode' => 'worker']);

        self::assertSame($id, $dispatched);
        $queued = $checks->get($id);
        self::assertSame('queued', $queued['status']);
        $running = array_replace($queued, ['status' => 'running']);
        self::assertTrue($checks->update($id, $queued, $running));
        self::assertFalse($checks->update($id, $queued, $running));
        self::assertSame($running, $checks->get($id));
    }

    public function testDispatchFailureDoesNotLeaveAQueuedCheck(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $bus = $this->createMock(MessageBusInterface::class);
        $bus->method('dispatch')->willThrowException(new RuntimeException('queue unavailable'));
        try {
            (new KubernetesChecks($store, $bus))->queue('admin', 'test', []);
            self::fail('Expected queue failure.');
        } catch (RuntimeException $error) {
            self::assertSame('queue unavailable', $error->getMessage());
        }
        self::assertSame(0, (int) $store->db->fetchOne("SELECT COUNT(*) FROM operator_settings WHERE id LIKE 'kube-check:%'"));
    }
}
