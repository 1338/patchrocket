<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Remediation\ApprovalPolicy;
use App\Remediation\Change;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class ApprovalPolicyTest extends TestCase
{
    private Store $store;
    private ApprovalPolicy $policy;
    private string $repository;
    private Change $change;

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $inventory = new Inventory($this->store);
        $this->policy = new ApprovalPolicy($this->store, $inventory);
        $this->repository = $inventory->asset('repository', 'policy-fixture', 'Policy fixture');
        $this->change = new Change('fixture', 'composer', 'awaiting_approval', ['patch_sha256' => str_repeat('a', 64)]);
        $this->store->db->insert('changes', [
            'id' => $this->change->id, 'asset_id' => $this->repository, 'finding_id' => 'finding',
            'status' => $this->change->getStatus(), 'strategy' => $this->change->strategy,
            'created_at' => gmdate(DATE_ATOM), 'data' => Store::json($this->change->data),
        ]);
    }

    public function testPassingIndependentEvidenceForAnotherPatchDoesNotAllowApproval(): void
    {
        $this->policy->configure($this->repository, ['composer'], true);
        $this->store->record($this->change->id, 'independent', ['passed' => true, 'patch_sha256' => str_repeat('b', 64)]);
        $this->expectExceptionMessage('requires a passing independent verification');
        $this->policy->check($this->change);
    }

    public function testExactIndependentEvidenceCanSatisfyApprovalPolicy(): void
    {
        $this->policy->configure($this->repository, ['composer'], true);
        $ids = [$this->change->id];
        self::assertSame($this->policy->hold($this->change), $this->policy->pendingHolds($ids)[$this->change->id]);
        $this->store->record($this->change->id, 'independent', ['passed' => true, ...$this->change->data]);
        $this->policy->check($this->change);
        self::assertSame([], $this->policy->pendingHolds($ids));
        $this->policy->configure($this->repository, ['npm'], true);
        self::assertSame($this->policy->hold($this->change), $this->policy->pendingHolds($ids)[$this->change->id]);
        $this->expectExceptionMessage('held by the repository approval policy');
        $this->policy->check($this->change);
    }

    public function testPendingHoldsKeepTheRecordedPatchDigestType(): void
    {
        $this->policy->configure($this->repository, ['composer'], true);
        $this->change->data['patch_sha256'] = 17;
        $this->store->db->update('changes', ['data' => Store::json($this->change->data)], ['id' => $this->change->id]);
        $this->store->record($this->change->id, 'independent', ['passed' => true, 'patch_sha256' => '17']);

        $holds = $this->policy->pendingHolds([$this->change->id]);
        self::assertSame(ApprovalPolicy::INDEPENDENT_VERIFICATION_REQUIRED, $holds[$this->change->id]['code']);
        self::assertSame($this->policy->hold($this->change), $holds[$this->change->id]);
    }

    public function testIndependentEvidenceWithoutAPatchDigestDoesNotAllowApproval(): void
    {
        $this->policy->configure($this->repository, ['composer'], true);
        unset($this->change->data['patch_sha256']);
        $this->store->record($this->change->id, 'independent', ['passed' => true]);

        $this->expectExceptionMessage('requires a passing independent verification');
        $this->policy->check($this->change);
    }
}
