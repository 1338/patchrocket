<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Remediation\RunVmPackage;
use App\Remediation\VmPackages;
use App\Settings\Connections;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;

final class VmPackagesTest extends TestCase
{
    private Store $store;
    private Inventory $inventory;
    private Connections $connections;
    private VmPackages $packages;
    private string $asset;
    private string $connection;
    private array $messages = [];

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $this->inventory = new Inventory($this->store);
        $bus = $this->createStub(MessageBusInterface::class);
        $bus->method('dispatch')->willReturnCallback(function (object $message): Envelope {
            $this->messages[] = $message;

            return Envelope::wrap($message);
        });
        $this->connections = new Connections($this->store, $bus);
        $this->packages = new VmPackages($this->store, $this->inventory, $bus);
        $target = 'updater@vm.example.test';
        $this->asset = $this->inventory->asset('linux', 'ssh/'.$target, 'Fixture VM', [
            'ssh_alias' => $target, 'manager' => 'APT', 'distribution' => 'ubuntu',
        ]);
        $this->connection = $this->connections->save('vm', [
            'target' => $target, 'name' => 'Fixture VM', 'credential' => 'test:bundle', 'package_updates' => '1',
        ]);
    }

    public function testRequiresDiscoveryOnTheExactManagedConnection(): void
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('discover the host');
        $this->packages->prepare($this->asset, 'openssl', 'operator');
    }

    public function testOnlyAnActiveAptFindingWithAFixPrefillsItsHostPackage(): void
    {
        $asset = $this->inventory->get($this->asset);
        $finding = ['asset_id' => $this->asset, 'active' => 1, 'data' => [
            'package' => 'openssl:amd64', 'fixed' => '3.0.2-2', 'type' => 'ubuntu',
        ]];
        self::assertSame('openssl:amd64', VmPackages::findingPackage($asset, $finding));
        self::assertNull(VmPackages::findingPackage($asset, array_replace($finding, ['active' => 0])));
        self::assertNull(VmPackages::findingPackage($asset, array_replace($finding, ['asset_id' => str_repeat('a', 64)])));
        foreach (['fixed' => '', 'package' => 'openssl openssh', 'type' => 'npm'] as $field => $invalid) {
            $invalidFinding = array_replace($finding, ['data' => array_replace($finding['data'], [$field => $invalid])]);
            self::assertNull(VmPackages::findingPackage($asset, $invalidFinding));
        }
    }

    public function testRequiresReviewBeforeQueueingWriteAndRejectsStaleJob(): void
    {
        $job = $this->plan();
        try {
            $this->packages->approve($this->asset, $job['id'], '3.0.2-2', false, 'admin');
            self::fail('Approval without review must fail.');
        } catch (DomainException) {
            self::assertSame('awaiting_approval', $this->packages->job($this->asset)['status']);
        }
        $this->packages->approve($this->asset, $job['id'], '3.0.2-2', true, 'admin');
        self::assertSame('apply_queued', $this->packages->job($this->asset)['status']);
        self::assertEquals([
            new RunVmPackage($this->asset, $job['id'], 'plan'),
            new RunVmPackage($this->asset, $job['id'], 'apply'),
        ], $this->messages);
        $this->packages->cancel($this->asset, $job['id'], 'admin');
        $this->expectException(DomainException::class);
        $this->packages->approve($this->asset, $job['id'], '3.0.2-2', true, 'admin');
    }

    public function testApprovalBecomesStaleIfConnectionChanges(): void
    {
        $job = $this->plan();
        $row = $this->connections->get($this->connection);
        $this->connections->update($row, array_replace($row['data'], ['port' => '2222']));
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('connection changed');
        $this->packages->approve($this->asset, $job['id'], '3.0.2-2', true, 'admin');
    }

    public function testExpiredPlanCannotQueueAWrite(): void
    {
        $job = $this->plan();
        $this->packages->transition($job, array_replace($job, ['expires_at' => time() - 1]), 'worker');
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('plan expired');
        $this->packages->approve($this->asset, $job['id'], '3.0.2-2', true, 'admin');
    }

    public function testQueueShowsApprovalExpiryWithoutChangingTheRecordedState(): void
    {
        $job = $this->plan();
        $active = $this->packages->queue('', 1, $job['expires_at'] - 1);
        self::assertSame('open', $active['state']);
        self::assertSame($this->asset, $active['rows'][0]['asset_id']);
        self::assertFalse($active['rows'][0]['approval_expired']);
        self::assertArrayNotHasKey('connection', $active['rows'][0]);

        $expired = $this->packages->queue('approval', 1, $job['expires_at']);
        self::assertTrue($expired['rows'][0]['approval_expired']);
        self::assertSame('awaiting_approval', $expired['rows'][0]['status']);
        self::assertSame('awaiting_approval', $this->packages->job($this->asset)['status']);
        self::assertSame([], $this->packages->queue('worker', 1, $job['expires_at'])['rows']);

        $exact = $this->packages->queue('worker', 3, $job['expires_at'], $this->asset);
        self::assertSame(['rows' => $expired['rows'], 'state' => 'worker', 'page' => 1, 'next' => false, 'asset' => $this->asset], $exact);
        self::assertSame([], $this->packages->queue('open', 1, $job['expires_at'], str_repeat('f', 64))['rows']);
        self::assertSame($expired, $this->packages->queue('approval', 1, $job['expires_at'], 'invalid'));
    }

    public function testHistoryKeepsReplacedAttemptsAndScopesEvidenceToTheAsset(): void
    {
        $old = $this->plan();
        $this->packages->cancel($this->asset, $old['id'], 'admin');
        $this->packages->prepare($this->asset, 'curl', 'admin');
        $history = $this->packages->history($this->asset, 1);
        self::assertSame(['curl', 'openssl'], array_map(static fn (array $row): string => $row['data']['package'], $history['rows']));
        self::assertSame(1, $this->packages->historyPageForAttempt($this->asset, $old['id']));
        self::assertNull($this->packages->historyPageForAttempt(str_repeat('f', 64), $old['id']));
        $attempt = $this->packages->historyAttempt($this->asset, $old['id'], 1);
        self::assertSame('cancelled', $attempt['job']['status']);
        self::assertSame(['plan_queued', 'awaiting_approval', 'cancelled'],
            array_map(static fn (array $row): string => $row['data']['status'], $attempt['events']));
        self::assertNull($this->packages->historyAttempt(str_repeat('f', 64), $old['id'], 1));
    }

    private function plan(): array
    {
        $row = $this->connections->get($this->connection);
        $this->connections->update($row, $row['data'] + ['last_discovery' => ['status' => 'complete', 'asset_id' => $this->asset]]);
        $this->packages->prepare($this->asset, 'openssl', 'operator');
        $job = $this->packages->job($this->asset);
        $planned = array_replace($job, [
            'status' => 'awaiting_approval', 'expires_at' => $this->packages->reviewDeadline(),
            'plan' => ['machine' => str_repeat('a', 64), 'name' => 'openssl', 'architecture' => 'amd64', 'previous' => '3.0.2-1', 'version' => '3.0.2-2'],
        ]);
        $this->packages->transition($job, $planned, 'worker');

        return $planned;
    }
}
